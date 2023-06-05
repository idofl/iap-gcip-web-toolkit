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

import {HttpServerRequestHandler} from '../utils/http-server-request-handler';
import requestPromise = require('request-promise');

export interface GcipToken {
  verifyAccessToken(): Promise<boolean>;
  getNameIdentifier(token: any): string;
}

const REFRESH_TOKEN_URL =
    'https://securetoken.googleapis.com/v1/token?key=';

const CLIENT_CERT_URL = 
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/** Time offset in milliseconds for forcing a refresh before a token expires. */
export const OFFSET = 30000;
/** Network request timeout duration. */
const TIMEOUT_DURATION = 10000;

/** Utility used to manage OAuth access tokens generated via GCIP. */
export class GcipTokenManager implements GcipToken {
  private readonly googleSigningCertRetriever: HttpServerRequestHandler;
  private expirationTime: number;
  private clientCerts: any;
  private accessToken: string | null;
  private refreshToken: string | null;
  private apiKey: string;

  /**
   */
  constructor(accessToken:string, refreshToken: string, apiKey: string) {
    this.googleSigningCertRetriever = new HttpServerRequestHandler({
      method: 'GET',
      url: CLIENT_CERT_URL,
      timeout: TIMEOUT_DURATION,
    });
   
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.apiKey = apiKey;
  }

  private async RefreshToken() {

  }

  getNameIdentifier(token: any): string {
    return token.email || token.firebase.identities[token.firebase.sign_in_provider][0];
  }

  async verifyAccessToken(allowRefresh:boolean=true): Promise<any> {
    if (!this.clientCerts) {
      const httpResponse = await this.googleSigningCertRetriever.send(null, "Unable to retrieve Google's signing certificate");
      
      if (httpResponse.statusCode === 200 && httpResponse.body) {
          this.clientCerts = httpResponse.body;
      } else {
          throw new Error("Unable to retrieve Google's signing certificate");
      }
    }

    var jwt = require('jsonwebtoken');
    const decodedToken = jwt.decode(this.accessToken, {complete: true});
    const kid = decodedToken.header.kid;
    if (this.clientCerts[kid]) {
      try {
        const decoded = jwt.verify(this.accessToken, this.clientCerts[kid]);
        return decoded;
      } catch(err) {
          if (err.name == 'TokenExpiredError' && allowRefresh) {
            // Refresh the token and retry
            const options = { 
              method: 'POST',
              uri: REFRESH_TOKEN_URL+this.apiKey,
              form: {
                grant_type: 'refresh_token',
                refresh_token: this.refreshToken,
              },
            }

            try {
              const result = await requestPromise(options);
              this.accessToken = JSON.parse(result).access_token;
            } catch (err) {
              throw new Error(`Failed refreshing access token: ${err.message}`);
            }

            // Retry validation with a new access token (no refresh this time!)
            return await this.verifyAccessToken(false);
          }
          throw new Error(`Failed verifying JWT of user: ${err.message}`);
      }
    }
    else {
      throw new Error("JWT signing cert not found");
    }
  }
}
