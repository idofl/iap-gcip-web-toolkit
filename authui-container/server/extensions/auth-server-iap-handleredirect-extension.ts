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
import { ERROR_MAP } from '../utils/error';

import express = require('express');

export class iapRedirectExtension implements AuthServerExtension {
  private authServer : AuthServer; 

  apply(authServer: AuthServer, app: express.Application) : Promise<void> {
    console.log("Adding endpoint /handleRedirect to handle IAP signout redirects");

    this.authServer = authServer;

    app.post('/handleRedirect', async (req: express.Request, res: express.Response) => {
      if (!isNonNullObject(req.body) ||
        Object.keys(req.body).length === 0) {
          this.authServer.handleErrorResponse(res, ERROR_MAP.INVALID_ARGUMENT);
      } else {
        const iapConfigs: UiConfig = await this.authServer.getFallbackConfig(req.hostname);
        const redirectUrl = req.body.state as string;
        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify({
          originalUri: redirectUrl,
          targetUri: redirectUrl,
          tenantIds: Object.keys(Object.values(iapConfigs)[0].tenants),
        }));
      }
    });
    return;
  }
}

AuthServerRegisteredExtensions.getInstance().register(new iapRedirectExtension());