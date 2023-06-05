/*
 * Copyright 2023 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as saml2 from 'saml2-js';
import { SamlSignInOption } from './gcip-handler';
import { SigningCertManager} from './signing-cert-manager';

/** Interface defining a SAML request handler */
export interface SamlRequestHandler {
  getSamlLogoutUrl(providerConfig: SamlSignInOption, nameIdentifier: string, nameIdFormat: string, relayState: string, sessionIndex: string): Promise<string>;
}

export class SamlLogoutRequestRequest {
  destination: string;
  issuer: string;
  nameId: string;
  nameIdFormat: string;
  privateKey: Buffer;
  publicKey: Buffer;
  relayState: string;
  sessionIndex: string;
}

export class SamlManager implements SamlRequestHandler {
  private certManager:  SigningCertManager;

  constructor (certManager:  SigningCertManager) {
    this.certManager = certManager;
  }

  async getSamlLogoutUrl(
    providerConfig: SamlSignInOption, 
    nameIdentifier: string, 
    nameIdFormat: string, 
    relayState: string = null, 
    sessionIndex: string = null): Promise<string> {
    
    const config: SamlSignInOption = providerConfig as SamlSignInOption;
    
    let publicKey = await this.certManager.getPublicKey(true);
    let privateKey = await this.certManager.getPrivateKey();

    let samlLogoutRequestOptions = new SamlLogoutRequestRequest();
    samlLogoutRequestOptions.destination = config.idpUrl;
    samlLogoutRequestOptions.issuer = config.issuerId;
    samlLogoutRequestOptions.nameId = nameIdentifier;
    samlLogoutRequestOptions.privateKey = privateKey;
    samlLogoutRequestOptions.publicKey = publicKey;
    samlLogoutRequestOptions.relayState = relayState;
    samlLogoutRequestOptions.nameIdFormat = nameIdFormat;
    samlLogoutRequestOptions.sessionIndex = sessionIndex;
    let samlLogoutRequest: string = 
      await this.createSamlLogoutRequest(samlLogoutRequestOptions);

    return samlLogoutRequest;
  }

  private async createSamlLogoutRequest(request: SamlLogoutRequestRequest): Promise<string> {
    const sp_options = {
      entity_id: request.issuer,
      private_key: request.privateKey.toString(),
      certificate: request.publicKey.toString(),
      assert_endpoint: '',
    };
    const sp = new saml2.ServiceProvider(sp_options);

    const idp_options = {
      sso_login_url: '',
      sso_logout_url: request.destination,
      assert_endpoint: '',
      certificates: '',
    };
    const idp = new saml2.IdentityProvider(idp_options);

    let options = {
      name_id: request.nameId,
      sign_get_request: true,
      session_index: request.sessionIndex,
      relay_state: request.relayState,
    };
  
    if (!options.session_index) 
      delete options.session_index;

    if (!options.relay_state) 
      delete options.relay_state;

    let func = new Promise<string>((resolve) => {
      sp.create_logout_request_url(idp, options, function(err: any, logout_url: string): void {
        if (err != null)
          resolve(null)
        else
          resolve(logout_url);
      })
    });
  
    return func;
  }
}
