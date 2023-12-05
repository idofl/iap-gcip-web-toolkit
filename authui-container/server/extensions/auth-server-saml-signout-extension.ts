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

import { AuthServer } from "../auth-server";
import { AuthServerExtension, AuthServerRegisteredExtensions } from "../auth-server-extension";
import { isNonNullObject } from '../../common/validator';
import { ERROR_MAP } from '../utils/error';
import { GcipTokenManager } from "../api/gcip-token-manager";
import { SignInOption, SamlSignInOption } from '../api/gcip-handler';
import { UiConfig } from '../../common/config';
import { SamlManager} from './saml-manager';
import { SecretManagerSigningCertManager} from './signing-cert-manager';

import express = require('express');

/**
 * Depending on the DEBUG_CONSOLE environment variable, this will log the provided arguments to the console.
 * @param args The list of arguments to log.
*/
function log(...args: any[]) {
  if (process.env.DEBUG_CONSOLE === 'true' || process.env.DEBUG_CONSOLE === '1') {
    // tslint:disable-next-line:no-console
    console.log.apply(console, arguments);
  }
}

class samlSignOutExtension implements AuthServerExtension {
  private authServer : AuthServer; 
  private certManager: SecretManagerSigningCertManager = new SecretManagerSigningCertManager();

  apply(authServer: AuthServer, app: express.Application) : Promise<void> {
    console.log("Adding endpoints for SAML signout to external IdPs");

    this.authServer = authServer;

    app.post('/__/saml_logout_response', async (req: express.Request, res: express.Response) => {
      if (!isNonNullObject(req.body) ||
        Object.keys(req.body).length === 0) {
        this.authServer.handleErrorResponse(res, ERROR_MAP.INVALID_ARGUMENT);
      } else {
        this.handleRelayStateRedirect(req.body.RelayState, req, res);
      }
    });

    app.get('/__/saml_logout_response', async (req: express.Request, res: express.Response) => {
      // Use the RelayState to return to the signout URL initially started by IAP
      this.handleRelayStateRedirect(req.query.RelayState as string, req, res);
    });

    app.get('/__/signout', async (req: express.Request, res: express.Response) => {
      try {
        const relayState = req.query.relayState as string;
        const sessionIndex = req.query.sessionIndex as string;
        const apiKey = req.query.apiKey as string;
        const accessToken = req.query.accessToken as string;
        const refreshToken = req.query.refreshToken as string;

        let response = null;
        // PROVIDERS_FOR_SAML_LOGOUT example:
        // [{"tenant","provider":"saml.adfs", "nameIdFormat":"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress"}]",
      //"PROVIDERS_FOR_SAML_LOGOUT": "[{\"provider\":\"saml.adfs\", \"nameIdFormat\":\"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress\", "includeRelayState": "false"}]",

        let supportedProviders :any[]= JSON.parse(process.env.PROVIDERS_FOR_SAML_LOGOUT || '[]');
        if (!supportedProviders || supportedProviders.length == 0) {
          // This is not an error.
          log('No providers found for single sign-out from external IdPs');
        }

        // Verify the access token is valid before proceeding with the sign out
        const gcipTokenManager = new GcipTokenManager(accessToken, refreshToken, apiKey);
        const userToken = await gcipTokenManager.verifyAccessToken();

        let tenantId = userToken.firebase.tenant as string;
        // Set default tenant if no tenant was provided
        if (!tenantId) {
          tenantId = '_';
        }

        // Verify the provider is configured for IdP sign out
        const providerId = userToken.firebase.sign_in_provider;
        const providerInfo = supportedProviders.find((config) => (config.tenantId || '_') == tenantId && config.provider == providerId);
        if (providerInfo){
          const iapConfigs: UiConfig = await this.authServer.getFallbackConfig(req.hostname);

          if (iapConfigs.hasOwnProperty(apiKey)) {
            // Locate the tenant and provider config
            const iapConfig = iapConfigs[apiKey];
            let config = iapConfig.tenants[tenantId];
            if (config) {
              const providerId = userToken.firebase.sign_in_provider;
              const providerConfig : SignInOption= 
              config.signInOptions.find((provider: SignInOption)=>provider.provider == providerId) as SignInOption;

              if (providerConfig) {
                const userNameIdentifier = gcipTokenManager.getNameIdentifier(userToken);

                if (providerId.startsWith('saml')) {
                  const samlProviderConfig = providerConfig as SamlSignInOption;

                  log(`Preparing to sign out user ${userNameIdentifier} from external IdP (${samlProviderConfig.provider}).`);
                  samlProviderConfig.idpUrl = providerInfo.sloUrl ?? samlProviderConfig.idpUrl;
                  let samlManager = new SamlManager(this.certManager);

                  const redirectUrl = await samlManager.getSamlLogoutUrl(
                    samlProviderConfig,
                    userNameIdentifier,
                    providerInfo.nameIdFormat,
                    providerInfo.includeRelayState ? relayState : null,
                    sessionIndex);

                  response = {
                      method: 'Redirect',
                      url: redirectUrl,
                      data: null
                  }

                  log(`Generated SAML sign out request for user ${userNameIdentifier}:\n${redirectUrl}`);
                } else {
                  this.authServer.handleErrorResponse(res, {
                    error: {
                        code: 400,
                        status: 'INVALID_ARGUMENT',
                        message: 'Only SAML sign out is supported at this time',
                    }
                  });
                  log(`Could not generate signout request for user ${userNameIdentifier}: Unsupported provider`);
                }
              } else {
                this.authServer.handleErrorResponse(res, {
                  error: {
                      code: 400,
                      status: 'INVALID_ARGUMENT',
                      message: 'Could not find provider configuration for the signed in user',
                  }
                });
              }
            } else {
              this.authServer.handleErrorResponse(res, {
                error: {
                    code: 400,
                    status: 'INVALID_ARGUMENT',
                    message: 'Could not find tenant configuration for the signed in user',
                }
              });
            }
          } else {
            // apiKey not found
            this.authServer.handleErrorResponse(res, {
              error: {
                  code: 400,
                  status: 'INVALID_ARGUMENT',
                  message: 'Invalid apiKey',
              },
            });
          }
        }
        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify(response));
      } catch (err) {
        log(err);
        this.authServer.handleError(res, err);
      }
    });

    return this.certManager.init();;
  }

  private handleRelayStateRedirect(relayState: string, req: express.Request, res: express.Response): void {
    if (relayState) {
      const redirectUrl = Buffer.from(relayState, 'base64').toString();
      const currentOrigin = `${req.protocol}://${req.get('host')}`;
      if (new URL(redirectUrl).origin == currentOrigin) {
        res.redirect(redirectUrl);
        res.end();
      } else {
        this.authServer.handleErrorResponse(res, {
          error: {
              code: 400,
              status: 'INVALID_ARGUMENT',
              message: 'Cannot redirect to a different site than the current.',
          },
        });
      } 
    } else {
      res.set('Content-Type', 'application/json');
      res.send(JSON.stringify(req.originalUrl));
      res.end();
    }
  }
}

AuthServerRegisteredExtensions.getInstance().register(new samlSignOutExtension());
