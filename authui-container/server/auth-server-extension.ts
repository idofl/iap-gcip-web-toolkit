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

import { AuthServer } from "./auth-server";

export interface AuthServerExtension {
  applyPreProxy: (authServer : AuthServer, app: Express.Application) => Promise<void>
  applyPostProxy: (authServer : AuthServer, app: Express.Application) => Promise<void>
}

export class AuthServerRegisteredExtensions {
  private static instance: AuthServerRegisteredExtensions;

  private extensions: Array<AuthServerExtension>;

  private constructor () {
    this.extensions = new Array<AuthServerExtension>();
  }

  public static getInstance(): AuthServerRegisteredExtensions {
    if (!AuthServerRegisteredExtensions.instance) {
      AuthServerRegisteredExtensions.instance = new AuthServerRegisteredExtensions();
    }

    return AuthServerRegisteredExtensions.instance;
}

  public register(extension: AuthServerExtension) : void {
    this.extensions.push(extension);
  }

  public invokePreProxy(authServer : AuthServer, app: Express.Application) : Promise<void> {
    // Run through the extensions sequentially
    return this.extensions
      .map((ext) => ext.applyPreProxy(authServer, app))
      .reduce((prev, cur) => prev.then(()=> cur), Promise.resolve());
  }

  public invokePostProxy(authServer : AuthServer, app: Express.Application) : Promise<void> {
    // Run through the extensions sequentially
    return this.extensions
      .map((ext) => ext.applyPostProxy(authServer, app))
      .reduce((prev, cur) => prev.then(()=> cur), Promise.resolve());
  }
}