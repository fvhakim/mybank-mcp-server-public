import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { z } from "zod";
import express, { Request, Response, RequestHandler } from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { jwtVerify, createRemoteJWKSet } from "jose";

var MCP_ACCESS_TOKEN = "new_token";
var  MYBANK_API_1_ACCESS_TOKEN = "new_token";
var  MYBANK_API_2_ACCESS_TOKEN = "new_token";


const AUTH0_DOMAIN = "<domain-name>.us.auth0.com";
const AUTH0_AUDIENCE = "https://mcp.mybank.com";

const MYBANK_API_1_AUTH0_DOMAIN = "<domain-name>.us.auth0.com";
const MYBANK_API_1_CLIENT_ID = "<CLIENT_ID_FOR_API-1>";
const MYBANK_API_1_CLIENT_SECRET = "<CLIENT_SECRET_FOR_API-1>";
const MYBANK_API_1_AUDIENCE = "https://mybank-api-1.test";
const MYBANK_API_1_SCOPE = "read:balance";
const MYBANK_API_1_URL = "<URL_FOR_HOSTED_API_1>";


const MYBANK_API_2_AUTH0_DOMAIN = "<domain-name>.us.auth0.com"
const MYBANK_API_2_CLIENT_ID = "<CLIENT_ID_FOR_API-2>";
const MYBANK_API_2_CLIENT_SECRET = "<CLIENT_SECRET_FOR_API-2>";
const MYBANK_API_2_AUDIENCE = "https://mybank-api-2.test";
const MYBANK_API_2_SCOPE = "transfer:money";
const MYBANK_API_2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE = "urn:mybank:api:2";
const MYBANK_API_2_URL = "<URL_FOR_HOSTED_API_2>";

interface mybank_api_accessToken {
  access_token: string;
  token_type: string;
  expires_in: number;
}

// Create server instance

const server = new McpServer({
  name: "MyBank",
  version: "1.0.0",
  capabilities: {
    resources: {},
    tools: {},
  },
});



/******************* Auth0 auth settings *******************/

const mcpMetadataRouter = (): RequestHandler => {
  const router = express.Router()

  router.use("/.well-known/oauth-authorization-server", metadataHandler({
    issuer: `https://${AUTH0_DOMAIN}`,
    authorization_endpoint: new URL("/authorize", `https://${AUTH0_DOMAIN}`).href,
    token_endpoint: new URL("/oauth/token", `https://${AUTH0_DOMAIN}`).href,
    registration_endpoint: new URL("/oidc/register", `https://${AUTH0_DOMAIN}`).href,

    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
    scopes_supported: ["openid", "profile", "email", "read:userinfo"],
    default_scope: "openid profile email read:userinfo"
  }))

  return router
}

const requireAuth = (): RequestHandler => {
  return async (req, res, next) => {
    try {
      const header = req.headers.authorization;

      if (!header) {
        throw new InvalidTokenError("Missing Authorization header");
      }

      var [type, token] = header.split(' ');
      if (type.toLowerCase() !== 'bearer' || !token) {
        throw new InvalidTokenError("Invalid Authorization header format, expected 'Bearer TOKEN'");
      }
      MCP_ACCESS_TOKEN= token;
      
      // validate the MCP client token

      validateToken(token).then(result =>{

        if (! result)
      {
         throw new InvalidTokenError("Invalid Token");
      }
          else {console.log ("MCP client token is valid!")}

      });

      
      next()

    } catch (error) {
      if (error instanceof InvalidTokenError) {
        res.set("WWW-Authenticate", `Bearer error="${error.errorCode}", error_description="${error.message}"`);
        res.status(401).json(error.toResponseObject());
      } else {
        console.error("Unexpected error authenticating bearer token:", error);
        res.status(500).json(new ServerError("Internal Server Error").toResponseObject())
      }
    }
  }
}

/* ******************************************************** */
 


/******************* Code for Validating Auth0 issued accessTokens *******************/


const JWKS = createRemoteJWKSet(new URL(`https://${AUTH0_DOMAIN}/.well-known/jwks.json`));

async function validateToken(token: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, JWKS, {
    audience: AUTH0_AUDIENCE,
    issuer: `https://${AUTH0_DOMAIN}/`,
    });
    return true; // valid token

  } catch (err) {
    return false
    
  }
}

const MYBANK_API_1_JWKS = createRemoteJWKSet(new URL(`https://${MYBANK_API_1_AUTH0_DOMAIN}/.well-known/jwks.json`));

async function validateAPI1Token(token: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, MYBANK_API_1_JWKS, {
    audience: MYBANK_API_1_AUDIENCE,
    issuer: `https://${MYBANK_API_1_AUTH0_DOMAIN}/`,
    });


    return true; // valid token

  } catch (err) {
    console.log(err);
    return false
    
  }
}

const MYBANK_API_2_JWKS = createRemoteJWKSet(new URL(`https://${MYBANK_API_2_AUTH0_DOMAIN}/.well-known/jwks.json`));

async function validateAPI2Token(token: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, MYBANK_API_2_JWKS, {
    audience: MYBANK_API_2_AUDIENCE,
    issuer: `https://${MYBANK_API_2_AUTH0_DOMAIN}/`,
    });


    return true; // valid token

  } catch (err) {
    console.log(err);
    return false
    
  }
}

/* ******************************************************** */


// Register MyBank tools

// 1 - get the bank name. it will return the bank name from this MCP server, no API call.

server.tool(
  "bank_name",
  "get my bank name",
  async () => {
     
    const bankName = "My Bank";


   const bankText = "Welcome to the AI world. Your bank name is:  '" +  bankName + "' Its a demo bank to show how you can create MCP server for your services and APIs, secure it with Auth0 and make it available for any AI agent to use it securely";

    return {
      content: [
        {
          type: "text",
          text: bankText,
        },
      ],
    };
  },
);

// 2 - get your email - the MCP server will call /userinfo endpoint of Auth0 using the MCP client access token (that was recieved Earlier from Auth0).

server.tool(
  "get_my_email",
  "get my email of my bank, related to any bank acount, it will call the identity provider of the bank which is Auth0",
  async () => {
     
    var myEmail = null;
    try {
    const user = await getUserInfo(MCP_ACCESS_TOKEN);
    myEmail = user.email;
    console.log ("MCP client accessToken:", MCP_ACCESS_TOKEN);
    console.log("The recieved User profile from /userinfo endpoint using the MCP client accessToken:", user);
  } catch (err) {
    console.error(" Error fetching user info:", err);
  }

    
    if (!myEmail) {
      return {
        content: [
          {
            type: "text",
            text: "Failed to retrieve your email",
          },
        ],
      };
    }


   const emailText = "Your email on bank is: " +  myEmail;

    return {
      content: [
        {
          type: "text",
          text: emailText,
        },
      ],
    };
  },
);



interface Auth0UserInfo {
  sub: string;
  name?: string;
  nickname?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  updated_at?: string;
  [key: string]: unknown; // allow extra custom claims
}

async function getUserInfo(accessToken: string): Promise<Auth0UserInfo> {
  const res = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!res.ok) {
    const error = await res.text();
    throw new Error(`Auth0 userinfo failed: ${res.status} ${error}`);
  }

  return res.json() as Promise<Auth0UserInfo>;
}



/* 3 - get account balance - MCP server will get your bank account balance by calling Mybank-API1 using Auth0 accessToken that was requested  using client_credential flow. 
Once recieved, MCP server will save it until it expire  and request a new one from Auth0  */

server.tool(
  "get_balance",
  "get my bank balance",
  {
    account_number: z.string().length(5).describe("5 digit account number"),
  },
  async ({ account_number }) => {
    
    const myBalanceData = await getBalance( account_number ) ;
    console.log("Bank account balance from MyBank-API-1 using the above AccessToken is: " + myBalanceData.balance);
   
    if (!myBalanceData) {
      return {
        content: [
          {
            type: "text",
            text: "Failed to retrieve bank balance",
          },
        ],
      };
    }


   const balanceText = "balance for" + account_number + "is " +  myBalanceData.balance;

    return {
      content: [
        {
          type: "text",
          text: balanceText,
        },
      ],
    };
  },
);




async function getAccessTokenAPI1(): Promise<mybank_api_accessToken> {
  const url = `https://${MYBANK_API_1_AUTH0_DOMAIN}/oauth/token`; 

  const body = {
    client_id: MYBANK_API_1_CLIENT_ID,
    client_secret: MYBANK_API_1_CLIENT_SECRET,
    audience: MYBANK_API_1_AUDIENCE,
    scope: MYBANK_API_1_SCOPE,
    grant_type: "client_credentials",
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const error = await res.text();
    throw new Error(`Auth0 token request failed: ${res.status} ${error}`);
  }

  return (await res.json()) as mybank_api_accessToken;
}


interface balance {
  balance: string;
}

async function getBalance(account_number: string) : Promise<balance> {


  let isValid = await validateAPI1Token(MYBANK_API_1_ACCESS_TOKEN);

  if (!isValid) {
  
    const result = await getAccessTokenAPI1();
    MYBANK_API_1_ACCESS_TOKEN = result.access_token;
    console.log("New Access Token from Auth0 for MyBank-API-1:", MYBANK_API_1_ACCESS_TOKEN);
  } else {
    console.log("Existing Access Token from Auth0 for MyBank-API-1:", MYBANK_API_1_ACCESS_TOKEN);
  }

  const body = { "account_number" : account_number };

  const res = await fetch(MYBANK_API_1_URL + "/balance", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + MYBANK_API_1_ACCESS_TOKEN,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const error = await res.text();
    throw new Error(`Auth0 token request failed: ${res.status} ${error}`);
  }

  return res.json() as Promise<balance>;
}


/* 4 - Transfer money - this MCP server will call MyBank-API2 to transfer money using exchanged token. 
the MCP server will request exchanging the original recieved access token from the MCP client with an accessToken for MyBank-API2.
Once recieved, MCP server will save it until it expire and request/exchange a new one from Auth0 */


server.tool(
  "transfer_money",
  "transfer money between 2 bank accounts",
  {
    account_number_sender: z.string().length(5).describe("5 digit account number"),
    account_number_receiver: z.string().length(5).describe("5 digit account number"),
    amount: z.string()
  },
  async ({ account_number_sender, account_number_receiver, amount }) => {
       
    //const transfer_confirmation_number = "#3982-20398AFT-12WR";
    const transfer = await getTransferConfirmation (account_number_receiver,account_number_sender, amount);

    if (!transfer) {
      return {
        content: [
          {
            type: "text",
            text: "Failed to transfer the money",
          },
        ],
      };
    }


   const transferText = amount + " was transfered from account number:" + account_number_sender + "to account number:" + account_number_receiver + "and the confirmation number is:" + transfer.transfer_confirmation_number ;

    return {
      content: [
        {
          type: "text",
          text: transferText,
        },
      ],
    };
  },
);



async function getAccessTokenAPI2(): Promise<mybank_api_accessToken> {
  const url = `https://${MYBANK_API_2_AUTH0_DOMAIN}/oauth/token`; 

  const body = {
    subject_token_type: MYBANK_API_2_TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE,
    client_id: MYBANK_API_2_CLIENT_ID,
    client_secret: MYBANK_API_2_CLIENT_SECRET,
    audience: MYBANK_API_2_AUDIENCE,
    scope: MYBANK_API_2_SCOPE,
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: MCP_ACCESS_TOKEN
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const error = await res.text();
    throw new Error(`Auth0 token exchange failed: ${res.status} ${error}`);
  }

  return (await res.json()) as mybank_api_accessToken;
}


interface transfer {
  transfer_confirmation_number: string;
}


async function getTransferConfirmation(reciever: string, sender: string, amount: string) : Promise<transfer> {


  let isValid = await validateAPI2Token(MYBANK_API_2_ACCESS_TOKEN);

  if (!isValid) {
  
    const result = await getAccessTokenAPI2();
    MYBANK_API_2_ACCESS_TOKEN = result.access_token;
    console.log("New EXCHANGED Access Token from Auth0 for MyBank-API-2:", MYBANK_API_2_ACCESS_TOKEN);
  } else {
    console.log("Existing EXCHANGED Access Token from Auth0 for MyBank-API-2:", MYBANK_API_2_ACCESS_TOKEN);
  }

  const body = { "reciever" : reciever, "sender": sender, "amount": amount };

  const res = await fetch(MYBANK_API_2_URL + "/transfer", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + MYBANK_API_2_ACCESS_TOKEN,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const error = await res.text();
    throw new Error(`Auth0 token request failed: ${res.status} ${error}`);
  }

  return res.json() as Promise<transfer>;
}



/******* Using Stdio Transport Layer for locally deployed MCP servers  *****

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("MyBank MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});

*******************************************/

/****** Using Streamable HTTP ( Server-Sent Events (SSE) ) Transport layer ******/

const transports: {[sessionId: string]: SSEServerTransport} = {}

const app = express()

app.use(mcpMetadataRouter());

app.get("/sse", requireAuth(), async (_: Request, res: Response) => {
  const transport = new SSEServerTransport('/messages', res)
  transports[transport.sessionId] = transport
  res.on("close", () => {
    delete transports[transport.sessionId]
  })
  await server.connect(transport)
})

app.post("/messages", requireAuth(), async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string
  const transport = transports[sessionId]
  if (transport) {
    await transport.handlePostMessage(req, res)
  } else {
    res.status(400).send('No transport found for sessionId')
  }
})

app.listen(process.env.PORT || 3000);

console.log('MCP Server is running ')
