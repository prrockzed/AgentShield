FROM node:20-alpine AS builder

ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app

# Add these two lines:
ARG NEXT_PUBLIC_GATEWAY_URL=http://localhost:8080
ENV NEXT_PUBLIC_GATEWAY_URL=$NEXT_PUBLIC_GATEWAY_URL

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- runner ----
FROM node:20-alpine AS runner

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

WORKDIR /app

COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

EXPOSE 3000

CMD ["npm", "run", "start"]
