import {
  isRpcAuthResponse,
  isRpcError,
  type shelly_rpc_auth_response_t,
  type shelly_rpc_auth_request_t,
  type shelly_rpc_method_params_t,
  type shelly_rpc_method_result_t,
  type shelly_rpc_method_t,
  type shelly_rpc_msg_request_t,
  type shelly_transport_rpc_options_t,
  type shelly_device_info_data_t,
} from '@taulfsime/shelly-rpc-ts';

import { DeviceTransportBase } from './base-transport.js';

type sha256_func_t = (data: string) => Promise<string> | string;

const WS_RETRY_BASE_DELAY = 500; // milliseconds
let cnonce: number | null = null;

async function prepareAuthPartialFrame(
  sha256: sha256_func_t,
  shaUserToken: string,
  nonce: shelly_rpc_auth_response_t['nonce'],
  nc: shelly_rpc_auth_response_t['nc']
): Promise<{
  cnonce: Required<shelly_rpc_auth_request_t['cnonce']>;
  response: Required<shelly_rpc_auth_request_t['response']>;
}> {
  if (!cnonce) {
    cnonce = Date.now();
  }

  const parts = [];
  parts.push(shaUserToken);
  parts.push(nonce);
  parts.push(nc);
  parts.push(cnonce);
  parts.push('auth');
  parts.push(await Promise.resolve(sha256('dummy_method:dummy_uri')));
  const response = await Promise.resolve(sha256(parts.join(':')));

  return {
    cnonce,
    response,
  };
}

export class DeviceWsInTransport<
  H extends string = `ws://${string}` | `wss://${string}`,
> extends DeviceTransportBase<H> {
  static RECONNECT_RETRIES_INFINITE = -1;
  static DEFAULT_RECONNECT_RETRIES = 5;

  private _ws: WebSocket | null = null;
  private _forceDisconnect = false;
  private _retries = 0;
  private _maxRetries: number;
  private _reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private _isReconnecting = false;
  private _authFrame: {
    nonce: shelly_rpc_auth_response_t['nonce'];
    realm: shelly_rpc_auth_response_t['realm'];
    nc: shelly_rpc_auth_response_t['nc'];
  } | null = null;
  private _userShaToken: string = '';
  private _sha256Func: sha256_func_t | null = null;

  constructor(
    clientId: string,
    host: H,
    sha256Func: sha256_func_t | null = null,
    options?: { maxRetries?: number }
  ) {
    super(clientId, host);
    this._maxRetries =
      options?.maxRetries || DeviceWsInTransport.DEFAULT_RECONNECT_RETRIES;
    this._sha256Func = sha256Func;
  }

  _onBegin(): Promise<void> {
    return new Promise((resolve, reject) => {
      const connect = () => {
        this._ws = new WebSocket(`${this.host.replace(/\/$/, '')}/rpc`);
        this._forceDisconnect = false;
        this._isReconnecting = false;

        this._ws.onopen = () => {
          this._retries = 0;
          this._isReconnecting = false;
          if (this._reconnectTimeout) {
            clearTimeout(this._reconnectTimeout);
            this._reconnectTimeout = null;
          }
          resolve();
        };

        this._ws.onerror = error => {
          console.debug('WebSocket error:', error);
        };

        this._ws.onmessage = event => {
          this.receive(JSON.parse(event.data.toString()));
        };

        this._ws.onclose = event => {
          if (this._forceDisconnect) {
            return;
          }

          // prevent multiple reconnection attempts
          if (this._isReconnecting) {
            return;
          }

          if (
            this._retries < this._maxRetries ||
            this._maxRetries === DeviceWsInTransport.RECONNECT_RETRIES_INFINITE
          ) {
            this._retries++;
            this._isReconnecting = true;

            const timeout =
              WS_RETRY_BASE_DELAY *
              Math.max(
                this._retries,
                DeviceWsInTransport.DEFAULT_RECONNECT_RETRIES
              );

            console.debug(
              `WebSocket disconnected (code=${event.code}), retrying with delay ${timeout}ms`,
              this._maxRetries ===
                DeviceWsInTransport.RECONNECT_RETRIES_INFINITE
                ? `retry #${this._retries}`
                : `${this._retries}/${this._maxRetries}`
            );

            this._reconnectTimeout = setTimeout(() => {
              this._reconnectTimeout = null;
              connect();
            }, timeout);
          } else {
            reject(
              new Error(
                `WebSocket disconnected after ${this._retries} retries (code=${event.code})`
              )
            );
          }
        };
      };
      connect();
    });
  }

  _onEnd(): Promise<void> {
    this._forceDisconnect = true;
    this._isReconnecting = false;

    if (this._reconnectTimeout) {
      clearTimeout(this._reconnectTimeout);
      this._reconnectTimeout = null;
    }

    this._ws?.close();
    this._ws = null;
    this._retries = 0;
    return Promise.resolve();
  }

  _onSend(req: shelly_rpc_msg_request_t<shelly_rpc_method_t>): boolean {
    if (!this._ws) {
      return false;
    }

    this._ws.send(JSON.stringify(req));
    return true;
  }

  async authenticate(
    id: shelly_device_info_data_t['id'],
    password: string
  ): Promise<void> {
    if (!this._sha256Func) {
      return Promise.reject(new Error('No SHA-256 function provided'));
    }

    if (!this._authFrame) {
      return Promise.reject(new Error('No challenge frame available'));
    }

    this._userShaToken = await Promise.resolve(
      this._sha256Func(['admin', id, password].join(':'))
    );
  }

  async rpcRequest<K extends shelly_rpc_method_t>(
    method: K,
    params: shelly_rpc_method_params_t<K>,
    options?: Omit<shelly_transport_rpc_options_t, 'auth'>
  ): Promise<shelly_rpc_method_result_t<K>> {
    if (!options) {
      options = {};
    }

    if (this._authFrame) {
      const nc = this._authFrame.nc;
      this._authFrame.nc++;

      //@ts-expect-error
      options.auth = await this._regenerateAuthFrames(nc);
    }

    try {
      const result = await super.rpcRequest(method, params, options);

      return result;
    } catch (error) {
      console.error(
        `RPC request failed ${method}(${JSON.stringify(params)}) -> (${JSON.stringify(options)})`,
        error
      );

      if (isRpcError(error)) {
        if (error.code === 401) {
          // Handle unauthorized error
          const response = JSON.parse(error.message);

          if (isRpcAuthResponse(response)) {
            this._authFrame = {
              nonce: response.nonce,
              realm: response.realm,
              nc: response.nc,
            };
          }

          return new Promise(() => {});
        }
      }

      // auth captured, rethrow the error
      throw error;
    }
  }

  private async _regenerateAuthFrames(nc: number) {
    if (!this._sha256Func) {
      throw new Error('No SHA-256 function provided');
    }

    if (!this._authFrame) {
      throw new Error('No challenge frame available');
    }

    const rpcAuth = await prepareAuthPartialFrame(
      this._sha256Func,
      this._userShaToken,
      this._authFrame.nonce,
      nc
    );

    return {
      ...this._authFrame,
      ...rpcAuth,
      nc,
      username: 'admin',
      algorithm: 'SHA-256',
    };
  }
}
