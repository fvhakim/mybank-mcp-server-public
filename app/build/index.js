import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { z } from "zod";
import express from "express";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { jwtVerify, createRemoteJWKSet } from "jose";
var MCP_ACCESS_TOKEN = "";
const AUTH0_DOMAIN = "fhakim-ai-demo.us.auth0.com";
const AUDIENCE = "https://my.api/userinfo";
const MYBANK_API_1_CLIENT_ID = "sba8pzNk4ziYLxlh8R4uy1Uuhy6A2qJH";
const MYBANK_API_1_CLIENT_SECRET = "5Vt6DHHclPBhaoz_5QokxztfwknsSsag0jNdGv26vK3ZAAiVS90Pbu51TtgUN2EY";
const MYBANK_API_1_AUDIENCE = "https://mybank-api-1-2d8f128d5f3f.herokuapp.com";
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
const mcpMetadataRouter = () => {
    const router = express.Router();
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
    }));
    return router;
};
const requireAuth = () => {
    return async (req, res, next) => {
        try {
            const header = req.headers.authorization;
            if (!header) {
                throw new InvalidTokenError("Missing Authorization header");
            }
            const [type, token] = header.split(' ');
            if (type.toLowerCase() !== 'bearer' || !token) {
                throw new InvalidTokenError("Invalid Authorization header format, expected 'Bearer TOKEN'");
            }
            MCP_ACCESS_TOKEN = token;
            validateToken(token);
            next();
        }
        catch (error) {
            if (error instanceof InvalidTokenError) {
                res.set("WWW-Authenticate", `Bearer error="${error.errorCode}", error_description="${error.message}"`);
                res.status(401).json(error.toResponseObject());
            }
            else {
                console.error("Unexpected error authenticating bearer token:", error);
                res.status(500).json(new ServerError("Internal Server Error").toResponseObject());
            }
        }
    };
};
/* ******************************************************** */
/******************* Validate Auth0 token *******************/
const JWKS = createRemoteJWKSet(new URL(`https://${AUTH0_DOMAIN}/.well-known/jwks.json`));
async function validateToken(token) {
    try {
        const { payload } = await jwtVerify(token, JWKS, {
            audience: AUDIENCE,
            issuer: `https://${AUTH0_DOMAIN}/`,
        });
        return payload; // valid token
    }
    catch (err) {
        throw new Error("Invalid token: " + err);
    }
}
/* ******************************************************** */
// Register MyBank tools
// 1 - get your bank account balance 
server.tool("get_balance", "get my bank balance", {
    account_number: z.string().length(5).describe("5 digit account number"),
}, async ({ account_number }) => {
    const token = await getAccessToken();
    console.log("Access Token from Auth0 for MyBank-API-1:", token.access_token);
    const myBalanceData = await getBalance(account_number, token.access_token);
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
    const balanceText = "balance for" + account_number + "is " + myBalanceData.balance;
    return {
        content: [
            {
                type: "text",
                text: balanceText,
            },
        ],
    };
});
async function getAccessToken() {
    const url = `https://${AUTH0_DOMAIN}/oauth/token`;
    const body = {
        client_id: MYBANK_API_1_CLIENT_ID,
        client_secret: MYBANK_API_1_CLIENT_SECRET,
        audience: MYBANK_API_1_AUDIENCE,
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
    return (await res.json());
}
async function getBalance(account_number, token) {
    const body = {
        account_number: account_number,
    };
    const res = await fetch("https://mybank-api-1-2d8f128d5f3f.herokuapp.com/balance", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Authorization": "Bearer " + token },
        body: JSON.stringify(body),
    });
    if (!res.ok) {
        const error = await res.text();
        throw new Error(`Auth0 token request failed: ${res.status} ${error}`);
    }
    return res.json();
}
// 2- transfer money 
server.tool("transfer_money", "transfer money between 2 bank accounts", {
    account_number_sender: z.string().length(5).describe("5 digit account number"),
    account_number_reciever: z.string().length(5).describe("5 digit account number"),
    amount: z.string()
}, async ({ account_number_sender, account_number_reciever, amount }) => {
    const transfer_confirmation_number = "#3982-20398AFT-12WR";
    if (!transfer_confirmation_number) {
        return {
            content: [
                {
                    type: "text",
                    text: "Failed to transfer the money",
                },
            ],
        };
    }
    const balanceText = amount + " was transfered from account number:" + account_number_sender + "to account number:" + account_number_reciever + "and the confirmation number is:" + transfer_confirmation_number;
    return {
        content: [
            {
                type: "text",
                text: transfer_confirmation_number,
            },
        ],
    };
});
// 3- get your email from the /userinfo endpoint using the MCP client access token 
server.tool("get_my_email", "get my email from my bank account", {
    account_number: z.string().length(5).describe("5 digit account number"),
}, async ({ account_number }) => {
    var myEmail = null;
    try {
        const user = await getUserInfo(MCP_ACCESS_TOKEN);
        myEmail = user.email;
        console.log("MCP client accessToken:", MCP_ACCESS_TOKEN);
        console.log("The recieved User profile from /userinfo endpoint using the MCP client accessToken:", user);
    }
    catch (err) {
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
    const balanceText = "Your email on bank account number: " + account_number + "is " + myEmail;
    return {
        content: [
            {
                type: "text",
                text: myEmail,
            },
        ],
    };
});
async function getUserInfo(accessToken) {
    const res = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    if (!res.ok) {
        const error = await res.text();
        throw new Error(`Auth0 userinfo failed: ${res.status} ${error}`);
    }
    return res.json();
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
const transports = {};
const app = express();
app.use(mcpMetadataRouter());
app.get("/sse", requireAuth(), async (_, res) => {
    const transport = new SSEServerTransport('/messages', res);
    transports[transport.sessionId] = transport;
    res.on("close", () => {
        delete transports[transport.sessionId];
    });
    await server.connect(transport);
});
app.post("/messages", requireAuth(), async (req, res) => {
    const sessionId = req.query.sessionId;
    const transport = transports[sessionId];
    if (transport) {
        await transport.handlePostMessage(req, res);
    }
    else {
        res.status(400).send('No transport found for sessionId');
    }
});
app.listen(process.env.PORT || 3000);
console.log('MCP Server is running ');
