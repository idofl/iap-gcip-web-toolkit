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
import {deepCopy} from './utils/index';
import {HttpClient, HttpRequestConfig} from './utils/http-client';
// Import FirebaseUI dependencies.
import * as firebaseui from 'firebaseui';
// Import GCIP/IAP module.
import * as ciap from 'gcip-iap';

// The expected network timeout duraiton in milliseconds.
const TIMEOUT_DURATION = 30000;

// The /__/signout HTTP request configuration.
const GET_IDP_SIGNOUT_PARAMS: HttpRequestConfig = {
  method: 'GET',
  url: '/__/signout',
  timeout: TIMEOUT_DURATION,
};

export class SignInUiStartWrapper {
  private httpClient: HttpClient;
  private ciapAuth: ciap.Authentication;

  constructor() {
    this.httpClient = new HttpClient();
  }

  public async start(ciapAuth: ciap.Authentication, config: any) : Promise<void> {
    this.ciapAuth = ciapAuth;
    const ciapParams = new URL(window.location.href).searchParams;
    const apiKey = ciapParams.get("apiKey");

    if (config.hasOwnProperty(apiKey)) {
      // Add a callback to store the user's info
      config[apiKey].callbacks.beforeSignInSuccess = (user) => {
        const tenantId = user.tenantId || '_';
        // "firebase:authUser:AIzaSyADteHYbopM590zCpEh00qa1RJ_2h5Qsbk:Tenant-1-xur4e"
        const userKey = `signed-in-user:${apiKey}:${tenantId}`; ;
        window.sessionStorage.setItem(userKey, JSON.stringify({
          name: user.email, // Store email for debug purposes
          tenantId: user.tenantId,
          providerId: user.providerData[0].providerId,
          nameId: user.email || user.providerData[0].uid,
        }));
        return user;
      }

      if (ciapParams.get("mode") == "signout") {
        // Attempt to sign-out from external IdPs.
        // If POST is used, then the code will continue after all tenants have signed out
        // If Redirect is used, then the page will be redirected to the IdP, and will load again
        // after signout is complete
        return this.signOutAllUsers(apiKey)
          .then((continueWithLoading) => {
            if (continueWithLoading) {
              // Log the hosted UI version.
              return this.ciapAuth.start();
            }
          });
      }
    }

    return this.ciapAuth.start();
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
    if (user.tenantId) {
      url.searchParams.set('tenantId', user.tenantId);
    }
    url.searchParams.set('providerId', user.providerId);
    url.searchParams.set('nameId', user.nameId);
    request.url = url.toString();

    const httpResponse = await this.httpClient.send(request);
    return httpResponse.data;
  }
}