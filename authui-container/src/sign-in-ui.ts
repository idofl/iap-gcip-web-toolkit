/*
 * Copyright 2020 Google Inc. All Rights Reserved.
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

import {deepCopy, setStyleSheet} from './utils/index';
import {HttpClient, HttpRequestConfig} from './utils/http-client';
import {getBrowserName, BrowserName} from './utils/browser';
import {UiConfig} from '/../common/config';
// Import FirebaseUI dependencies.
import * as firebaseui from 'firebaseui';
// Import GCIP/IAP module.
import * as ciap from 'gcip-iap';

// The expected network timeout duraiton in milliseconds.
const TIMEOUT_DURATION = 30000;
// The /config HTTP request configuration.
const GET_CONFIG_PARAMS: HttpRequestConfig = {
  method: 'GET',
  url: '/config',
  timeout: TIMEOUT_DURATION,
};
// The /__/signout HTTP request configuration.
const GET_IDP_SIGNOUT_PARAMS: HttpRequestConfig = {
  method: 'GET',
  url: '/__/signout',
  timeout: TIMEOUT_DURATION,
};
// The current version of the hosted UI.
export const HOSTED_UI_VERSION = '__XXX_HOSTED_UI_VERSION_XXX__';

/** Utility for handling sign-in with IAP external identities. */
export class SignInUi {
  private containerElement: HTMLElement;
  private titleElement: HTMLElement;
  private img: HTMLImageElement;
  private loadingSpinnerElement: HTMLElement | null;
  private separatorElement: HTMLElement;
  private ciapAuth: ciap.Authentication;
  private mainContainer: Element;
  private httpClient: HttpClient;

  /**
   * Instantiates a SignInUi instance for handling IAP external identities authentication.
   * @param container The container element / identifier where the UI will be rendered.
   */
  constructor(private readonly container: string | HTMLElement) {
    this.httpClient = new HttpClient();
    this.containerElement = typeof container === 'string' ? document.querySelector(container) : container;
    this.loadingSpinnerElement = document.getElementById('loading-spinner');
    const elements = document.getElementsByClassName('main-container');
    if (elements.length > 0 && elements[0]) {
      this.mainContainer = elements[0];
    } else {
      throw new Error(`.main-container element not found`);
    }
    if (!this.containerElement) {
      throw new Error(`Container element ${container} not found`);
    }
    this.titleElement = document.getElementById('title');
    if (!this.titleElement) {
      throw new Error(`#title element not found`);
    }
    this.separatorElement = document.getElementById('separator');
    if (!this.separatorElement) {
      throw new Error(`#separator element not found`);
    }
    this.img = document.getElementById('logo') as HTMLImageElement;
    if (!this.img) {
      throw new Error(`#logo element not found`);
    }
  }

  /** @return A promise that resolves after the authenticaiton instance is started. */
  render() {
    return this.getConfig()
      .then((configs) => {
        // Remove spinner if available.
        if (this.loadingSpinnerElement) {
          this.loadingSpinnerElement.remove();
        }
        this.setCustomStyleSheet(configs);
        const config = this.generateFirebaseUiHandlerConfig(configs);
        // This will handle the underlying handshake for sign-in, sign-out,
        // token refresh, safe redirect to callback URL, etc.
        const handler = new firebaseui.auth.FirebaseUiHandler(
            this.container, config);

        this.ciapAuth = new (ciap.Authentication as any)(handler, undefined, HOSTED_UI_VERSION);

        const ciapParams = new URL(window.location.href).searchParams;
        const apiKey = ciapParams.get("apiKey");

        if (ciapParams.get("mode") == "signout") {
          // Attempt to sign-out from external IdPs.
          // If POST is used, then the code will continue after all tenants have signed out
          // If Redirect is used, then the page will be redirected to the IdP, and will load again
          // after signout is complete
          return this.signOutAllUsers(
            apiKey);
        }
        return true;
      })
      .then((continueWithLoading)=>{
        if (continueWithLoading) {
          // Log the hosted UI version.
          this.ciapAuth.start();
        }
      })
      .catch((error) => {
        this.handlerError(error);
        throw error;
      });
  }

  private async signOutAllUsers(apiKey: string): Promise<Boolean> {
    // Use a copy of the key array, because we are removing items while iterating
    const userKeys = Object.keys(window.sessionStorage);
    let continueWithAppLoading = true;

    for (var i = 0; i < userKeys.length; i++) {
      if (userKeys[i].startsWith('signed-in-user:'))
      {
        let userKey = userKeys[i];
        // Get cached user before it is being signed out from GCIP
        const signedInUser = JSON.parse(window.sessionStorage.getItem(userKey));
        if (signedInUser) {
          // First clear the cache, to prevent endless loops
          // of signing out the user from the IdP
          window.sessionStorage.removeItem(userKey);
          // Sign out the user from the first tenant we find
          // Next tenant will sign out after returning from redirect
          const signOutInfo = await this.getIdpSignOutInfo(signedInUser, apiKey);
          if (signOutInfo && signOutInfo.method == 'Redirect') {
            continueWithAppLoading = false;
            // Current only redirect is supported
            window.location.href = signOutInfo.url;
            // For redirects - stop signing out users because we can 
            // only redirect once. Other users will be signed out
            // after the completion of the current sign out.
            break;
          }
        }
      }
    }

    return continueWithAppLoading;
  }

  /**
   * @return A promise that resolves with the redirect URL for
   * IdP signout
   */
  private async getIdpSignOutInfo(user: any, apiKey: string): Promise<any> {
    const relayState = btoa(window.location.href);
    const request = deepCopy(GET_IDP_SIGNOUT_PARAMS);
    const url = new URL(request.url, window.location.href);
    url.searchParams.set('apiKey', apiKey);
    url.searchParams.set('relayState', relayState);
    url.searchParams.set('accessToken', user.accessToken);
    url.searchParams.set('refreshToken', user.refreshToken);
    request.url = url.toString();

    const httpResponse = await this.httpClient.send(request);
    return httpResponse.data;
  }

  /**
   * @return A promise that resolves with the loaded configuration file from /config.
   */
  private getConfig(): Promise<UiConfig> {
    return this.httpClient.send(GET_CONFIG_PARAMS)
      .then((httpResponse) => {
        return httpResponse.data as UiConfig;
      })
      .catch((error) => {
        const resp = error.response;
        const errorData = resp.data;
        throw new Error(errorData.error.message);
      });
  }

  /**
   * Sets any custom CSS URL in the loaded configs to the current document.
   * @param configs The loaded configuration from /config.
   */
  private setCustomStyleSheet(configs) {
    for (const apiKey in configs) {
      if (configs.hasOwnProperty(apiKey) && configs[apiKey].styleUrl) {
        setStyleSheet(document, configs[apiKey].styleUrl);
        break;
      }
    }
  }

  /**
   * Generates the CIAPHandlerConfig from the loaded config.
   * @param configs The loaded configuration from /config.
   * @return The generate object containing the associated CIAPHandlerConfig.
   */
  private generateFirebaseUiHandlerConfig(
      configs): {[key: string]: firebaseui.auth.CIAPHandlerConfig} {
    // For prototyping purposes, only one API key should be available in the configuration.
    for (const apiKey in configs) {
      if (configs.hasOwnProperty(apiKey)) {
        const config = deepCopy(configs[apiKey]);
        const selectTenantUiTitle = config.selectTenantUiTitle;
        const selectTenantUiLogo = config.selectTenantUiLogo;
        config.callbacks = {
          selectTenantUiShown: () => {
            this.mainContainer.classList.remove('blend');
            this.titleElement.innerText = selectTenantUiTitle;
            if (selectTenantUiLogo) {
              this.img.style.display = 'block';
              this.img.src = selectTenantUiLogo;
              this.separatorElement.style.display = 'block';
            } else {
              this.img.style.display = 'none';
              this.separatorElement.style.display = 'none';
            }
          },
          selectTenantUiHidden: () => {
            this.titleElement.innerText = '';
          },
          signInUiShown: (tenantId) => {
            this.mainContainer.classList.remove('blend');
            const key = tenantId || '_';
            this.titleElement.innerText =
                config &&
                config.tenants &&
                config.tenants[key] &&
                config.tenants[key].displayName;
            if (config.tenants[key].logoUrl) {
              this.img.style.display = 'block';
              this.img.src = config.tenants[key].logoUrl;
              this.separatorElement.style.display = 'block';
            } else {
              this.img.style.display = 'none';
              this.separatorElement.style.display = 'none';
            }
          },
          beforeSignInSuccess: (user) => {
            const tenantId = user.tenantId || '_';
            const userKey = `signed-in-user:${apiKey}:${tenantId}`; ;
            window.sessionStorage.setItem(userKey, JSON.stringify({
              name:user.email, // Store email for debug purposes
              accessToken: user._delegate.accessToken,
              refreshToken: user.refreshToken,
            }));
            return user;
          }
        };
        // Do not trigger immediate redirect in Safari without some user
        // interaction.
        for (const tenantId in (config.tenants || {})) {
          if (config.tenants[tenantId].hasOwnProperty('immediateFederatedRedirect')) {
            config.tenants[tenantId].immediateFederatedRedirect =
                config.tenants[tenantId].immediateFederatedRedirect && getBrowserName() !== BrowserName.Safari;
          }
        }
        // Remove unsupported FirebaseUI configs.
        delete config.selectTenantUiLogo;
        delete config.selectTenantUiTitle;
        delete config.styleUrl;
        return {
          [apiKey]: config,
        };
      }
    }
    return null;
  }

  /**
   * Displays the error message to the end user.
   * @param error The error to handle.
   */
  private handlerError(error: Error) {
    // Remove spinner if available.
    if (this.loadingSpinnerElement) {
      this.loadingSpinnerElement.remove();
    }
    // Show error message: errorData.error.message.
    this.mainContainer.classList.remove('blend');
    this.separatorElement.style.display = 'none';
    this.titleElement.innerText = '';
    this.img.style.display = 'none';
    this.containerElement.innerText = error.message;
  }
}
