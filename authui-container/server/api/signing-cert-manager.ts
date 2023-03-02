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

import {SecretManagerServiceClient} from '@google-cloud/secret-manager';

export interface SigningCertManager {
  init(): Promise<void>;
  getPublicKey(keyOnly: boolean): Promise<Buffer>;
  getPrivateKey(): Promise<Buffer>;
}

export class SecretManagerSigningCertManager implements SigningCertManager {
  private client = new SecretManagerServiceClient();
  private certName: string;
  private passName: string;
  private cert: Buffer;
  private pass: Buffer;
  private privateKey: Buffer;
  private publicKey: Buffer;
  private publicKeyNoHeaders: Buffer

  constructor() {
    const projectId = process.env.SIGNING_SECRETS_PROJECT_ID;
    const certSecretName = process.env.SIGNING_CERT_SECRET;
    const certVersion = process.env.SIGNING_CERT_SECRET_VERSION;
    const passSecretName = process.env.SIGNING_CERT_PASS_PHRASE_SECRET;
    const passVersion = process.env.SIGNING_CERT_PASS_PHRASE_SECRET_VERSION;

    if (!projectId || !certSecretName || !certVersion || !passSecretName || !passVersion) {
      throw new Error("Missing signing certificate environment variables");
    }

    this.certName = `projects/${projectId}/secrets/${certSecretName}/versions/${certVersion}`;
    this.passName = `projects/${projectId}/secrets/${passSecretName}/versions/${passVersion}`;
  }

  async init() : Promise<void> {
    let cert: Buffer;

    let response = await this.client.accessSecretVersion({name: this.certName});
    this.cert = Buffer.from(response[0].payload.data);
    
    response = await this.client.accessSecretVersion({name: this.passName})
    this.pass = Buffer.from(response[0].payload.data);
  }

  async getPublicKey(keyOnly: boolean = false): Promise<Buffer>{
    if (!this.publicKey) {
      const pem = require("pem-promise");
      let cert = await pem.readPkcs12(
        this.cert, 
        { p12Password: this.pass.toString() });

      this.publicKey = cert.cert;

      let publicKeyExp: RegExpExecArray = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g.exec(this.publicKey.toString());
      this.publicKeyNoHeaders = Buffer.from(publicKeyExp[1].toString().replace(/[\n|\r\n]/g, ''));
    }

    return keyOnly ? this.publicKeyNoHeaders : this.publicKey;
  }
  
  async getPrivateKey(): Promise<Buffer> {
    if (!this.privateKey) {
      const pem = require("pem-promise");
      
      let cert = await pem.readPkcs12(
        this.cert, 
        { p12Password: this.pass.toString() });

      this.privateKey = cert.key;
    }
    return this.privateKey;
  }
}


