# Runs the published npm package over stdio (for directories that start the server to inspect it).
FROM node:22-slim
ENV NODE_ENV=production
RUN npm install -g @tollylabs/x402-mcp@0.4.1
USER node
ENTRYPOINT ["tolly-x402-mcp"]
