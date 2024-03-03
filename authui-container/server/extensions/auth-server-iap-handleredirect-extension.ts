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

import { AuthServer } from '../auth-server';
import { AuthServerExtension, AuthServerRegisteredExtensions } from '../auth-server-extension';
import { isNonNullObject } from '../../common/validator';
import { UiConfig } from '../../common/config';
import { ERROR_MAP, ErrorHandlers } from '../utils/error';

import express = require('express');
import cors = require('cors');

export class iapRedirectExtension implements AuthServerExtension {
  private authServer : AuthServer; 
  private permittedRedirectUrls : string[];

  applyBeforeProxy(authServer: AuthServer, app: express.Application) : Promise<void> {
    app.options('/', cors());
    app.get('/', cors());
    return;
  }

  applyAfterProxy(authServer: AuthServer, app: express.Application) : Promise<void> {
    console.log("Adding endpoint /handleRedirect to handle IAP signout redirects");

    this.authServer = authServer;
    this.permittedRedirectUrls = JSON.parse(process.env.PERMITTED_URLS_FOR_LOGOUT || '[]');

    app.post('/handleRedirect', async (req: express.Request, res: express.Response) => {
      if (!isNonNullObject(req.body) ||
        Object.keys(req.body).length === 0) {
          ErrorHandlers.handleErrorResponse(res, ERROR_MAP.INVALID_ARGUMENT);
      } else {
        const iapConfigs: UiConfig = await this.authServer.getFallbackConfig(req.hostname);
        let redirectUrl = req.body.state as string;

        if (!this.isRedirectUrlPermitted(redirectUrl)) {
          // If requested URL is not permitted, return a 400 response
          ErrorHandlers.handleErrorResponse(res, ERROR_MAP.INVALID_ARGUMENT);
        } else {
          res.set('Content-Type', 'application/json');
          res.send(JSON.stringify({
            originalUri: redirectUrl,
            targetUri: redirectUrl,
            tenantIds: Object.keys(Object.values(iapConfigs)[0].tenants),
          }));
        }
      }
    });
    return;
  }

  private isRedirectUrlPermitted(redirectUrl: string) : boolean {
    return this.permittedRedirectUrls.some((url) => {
      return redirectUrl.match(url.replace("\\\\", "\\"));
    });
  }
}

AuthServerRegisteredExtensions.getInstance().register(new iapRedirectExtension());