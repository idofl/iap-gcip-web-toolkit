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

import crypto = require('crypto');
import builder = require('xmlbuilder2');
import {v4 as uuidv4} from 'uuid';
import {SignedXml, FileKeyInfo} from 'xml-crypto';
import zlib = require('zlib');
import { SignInOption, SamlSignInOption } from './gcip-handler';
import { SigningCertManager} from './signing-cert-manager';

/** Interface defining a SAML request handler */
export interface SamlRequestHandler {
  simpleSignRequest(valueToSign: Buffer, privateKey: Buffer): string;
  getSamlLogoutUrl(providerConfig: SignInOption, user: any, nameIdFormat: string, relayState: string): Promise<string>;
}

export class SamlLogoutRequestRequest {
  destination: string;
  issuer: string;
  nameId: string;
  nameIdFormat: string;
  privateKey: Buffer;
  publicKey: Buffer;
  relayState: string;
}

export class SamlManager implements SamlRequestHandler {
  private certManager:  SigningCertManager;

  constructor (certManager:  SigningCertManager) {
    this.certManager = certManager;
  }

  simpleSignRequest(valueToSign: Buffer, privateKey: Buffer): string {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(valueToSign);
    const signature = signer.sign(privateKey, 'base64');
  
    return signature;
  }

  private xmlSignRequest(
    xmlToSign: string, 
    samlMessageName: string, 
    attributeToSign: string, 
    privateKey: Buffer, 
    publicKey: Buffer): string {

    var sign = new SignedXml();
    sign.addReference(`//*[local-name(.)="${samlMessageName}"]`,
      [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#"
      ],
      "http://www.w3.org/2001/04/xmlenc#sha256");
  
    sign.keyInfoProvider = {
      getKey(keyInfo?: Node): Buffer {
        return publicKey;
      },
      getKeyInfo(key: string, prefix: string): string {
        prefix = prefix ? prefix + ':' : prefix;
        return `<${prefix}X509Data><${prefix}X509Certificate>${publicKey}</${prefix}X509Certificate></${prefix}X509Data>`;
      },
      file: null
    }
    sign.signingKey = privateKey;
    sign.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sign.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    sign.computeSignature(xmlToSign,  {
        prefix: "ds",
        location: { reference: `//*[local-name(.)="${attributeToSign}"]`, action: "after" },
      });
  
    return sign.getSignedXml();
  }

  async getSamlLogoutUrl(providerConfig: SignInOption, user: any, nameIdFormat: string, relayState: string = null): Promise<string> {
    
    const config: SamlSignInOption = providerConfig as SamlSignInOption;
    const nameId = user.email;

    let publicKey = await this.certManager.getPublicKey(true);
    let privateKey = await this.certManager.getPrivateKey();

    let samlLogoutRequestOptions = new SamlLogoutRequestRequest();
    samlLogoutRequestOptions.destination = config.idpUrl;
    samlLogoutRequestOptions.issuer = config.issuerId;
    samlLogoutRequestOptions.nameId = nameId;
    samlLogoutRequestOptions.privateKey = privateKey;
    samlLogoutRequestOptions.publicKey = publicKey;
    samlLogoutRequestOptions.relayState = relayState;
    samlLogoutRequestOptions.nameIdFormat = nameIdFormat;
    let samlLogoutRequest: string = 
      this.createSamlLogoutRequest(samlLogoutRequestOptions);

    return samlLogoutRequest;
  }

  private createSamlLogoutRequest(request: SamlLogoutRequestRequest): string {
      // Create the SAML LogoutRequest
    let xmlString = this.createSamlRequestXml(
      request.destination,
      request.issuer,
      request.nameId,
      request.nameIdFormat
    );
  
    // Add XML Signature to the SAML message
    const samlMessage = this.xmlSignRequest(
      xmlString,
      'LogoutRequest',
      'Issuer',
      request.privateKey,
      request.publicKey
    );
  
    // Encode the SAML request to send it in a URL
    const samlMessageEncoded = this.deflateAndEncodeString(samlMessage);
  
    // Prepare SAML request for signing SAMLRequest=value[&RelayState=value]&SigAlg=value
    // https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf (3.4.4.1)
    const sigValue = encodeURIComponent('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
    
    let samlRequestValue;
    if (request.relayState) {
      samlRequestValue = Buffer.from(`SAMLRequest=${samlMessageEncoded}&RelayState=${encodeURIComponent(request.relayState)}&SigAlg=${sigValue}`);
    } else {
      samlRequestValue = Buffer.from(`SAMLRequest=${samlMessageEncoded}&SigAlg=${sigValue}`);
    }
    const signature = this.simpleSignRequest(samlRequestValue, request.privateKey);
    const signatureEncoded = encodeURIComponent(signature);    
   
    let samlRequestUrl: string = samlRequestValue + `&signature=${signatureEncoded}`;
  
    const logoutUrl = `${request.destination}?${samlRequestUrl}`;
    return logoutUrl;
  }

  private createSamlRequestXml(
    destination: string, 
    issuer: string, 
    nameId: string, 
    nameIdFormat: string =null) {
  
    const xml = builder.create(
      { 
        version: '1.0',
        namespaceAlias: { 
          samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
          saml: 'urn:oasis:names:tc:SAML:2.0:assertion' } 
      })
      .ele('@samlp', 'samlp:LogoutRequest')
        .att({
          ID: '_' + uuidv4(),
          Version: '2.0',
          IssueInstant: new Date().toISOString(),
          Destination: destination,
          Consent: 'urn:oasis:names:tc:SAML:2.0:consent:unspecified'
        })
      .ele('@saml', 'saml:Issuer').txt(issuer).up()
      .ele('@saml', 'saml:NameID').txt(nameId);
  
      if (nameIdFormat) {
        xml.att({
          Format: nameIdFormat
        })
      }
  
    return xml.up().end({ prettyPrint: true });
  }

  private deflateAndEncodeString(valueToSign: string) : string{
    const defaltedString: Buffer = zlib.deflateRawSync(valueToSign);
    const base64String: string = Buffer.from(defaltedString).toString('base64');
    const uriEncodedString: string = encodeURIComponent(base64String);
  
    return uriEncodedString;
  }
}
