// ----- Types
import type { RequestPayload, VerifiedPayload } from "@gitcoin/passport-types";
import type { Provider, ProviderOptions } from "../types";
import axios from "axios";

export type DiiaTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: string;
  refresh_token: string;
};

export type DiiaGetAccessTokenResponse = {
  user_id?: number;
  access_token?: string;
  token_type?: string;
  expires_in?: string;
  refresh_token?: string;
};

// Export a Dia Provider to carry out OAuth and return a record object
export class DiaProvider implements Provider {
  // Give the provider a type so that we can select it with a payload
  type = "Dia";

  // Options can be set here and/or via the constructor
  _options = {};

  // construct the provider instance with supplied options
  constructor(options: ProviderOptions = {}) {
    this._options = { ...this._options, ...options };
  }

  // verify that the proof object contains valid === "true"
  async verify(payload: RequestPayload): Promise<VerifiedPayload> {
    let valid = false,
      verifiedPayload: DiiaGetAccessTokenResponse = {};

    try {
      verifiedPayload = await getAccessTokenDiia(payload.proofs.code);
    } catch (e) {
      return { valid: false };
    } finally {
      valid = Boolean(verifiedPayload && verifiedPayload.user_id);
    }

    return {
      valid: valid,
      record: {
        id: verifiedPayload.user_id.toString(),
      },
    };
  }
}

const requestAccessToken = async (code: string): Promise<DiiaGetAccessTokenResponse> => {
  const clientId = process.env.DIIA_CLIENT_ID;
  const clientSecret = process.env.DIIA_CLIENT_SECRET;
  const redirectUri = process.env.DIIA_CALLBACK;

  try {
    // Exchange the code for an access token
    const tokenRequest = await axios.post(
      "https://test.id.gov.ua/get-access-token",
      `grant_type=authorization_code&code=${code}&client_id=${clientId}&client_secret=${clientSecret}&redirect_uri=${redirectUri}`
    );

    if (tokenRequest.status != 200)
      throw `Post for request returned status code ${tokenRequest.status} instead of the expected 200`;

    const tokenResponse = tokenRequest.data as DiiaTokenResponse;
    return tokenResponse;
  } catch (e: unknown) {
    const error = e as { response: { data: { error_description: string } } };
    // eslint-disable-next-line no-console
    console.error("Error when verifying diia account for user:", error.response?.data);
    throw e;
  }
};

const getAccessTokenDiia = async (code: string): Promise<DiiaGetAccessTokenResponse> => {
  // retrieve user's auth bearer token to authenticate client
  const base_token_info = await requestAccessToken(code);
  //   const accessToken =  base_token_info.access_token;
  // Now that we have an access token fetch the user details
  //   const userRequest = await axios.get("", {
  //     headers: { Authorization: `Bearer ${accessToken}` },
  //   });
  //   if (userRequest.status != 200) {
  //     throw `Get user request returned status code ${userRequest.status} instead of the expected 200`;
  //   }
  return base_token_info;
};
