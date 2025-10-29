import type {
  shelly_rpc_method_params_t,
  shelly_rpc_method_result_t,
  shelly_rpc_method_t,
  shelly_transport_rpc_options_t,
} from '@taulfsime/shelly-rpc-ts';
import { ShellyTransportBase } from '@taulfsime/shelly-rpc-ts';

type shelly_base_transport_params_t = ConstructorParameters<
  typeof ShellyTransportBase
>;

export abstract class DeviceTransportBase<
  H extends string = string,
> extends ShellyTransportBase {
  private _isBusy = false;
  private _beginPromise: Promise<void> | null = null;
  private _host: H;

  constructor(
    clientId: shelly_base_transport_params_t[0],
    host: H,
    params?: shelly_base_transport_params_t[1]
  ) {
    super(clientId, params);

    this._host = host;
  }

  begin(): Promise<void> {
    if (this._beginPromise) {
      return this._beginPromise;
    }

    if (this._isBusy) {
      throw new Error('Transport already busy');
    }

    this._isBusy = true;

    this._beginPromise = this._onBegin();
    return this._beginPromise;
  }

  end(): Promise<void> {
    if (!this._isBusy) {
      throw new Error('Transport is not active');
    }

    this._isBusy = false;
    this._beginPromise = null;
    return this._onEnd();
  }

  abstract _onBegin(): Promise<void>;
  abstract _onEnd(): Promise<void>;

  get host(): H {
    return this._host;
  }
}
