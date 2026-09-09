import { createServer } from "node:http";

if (!process.env.API_KEY) {
  throw new Error("API_KEY is required");
}

createServer((_request, response) => {
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("App started with its Keevault environment.\n");
}).listen(3000, "0.0.0.0", () => {
  console.log("Listening on port 3000");
});
