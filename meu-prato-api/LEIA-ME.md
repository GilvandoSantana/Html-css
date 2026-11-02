# Meu Prato API (Cloudflare Workers + D1)

Sistema isolado: só do Meu Prato. Worker `meuprato-api`, banco `meuprato-db`. Não usa nada de outros sistemas (GesCon etc.).

## Publicar (uma vez, no computador, plano grátis do Cloudflare)
```
cd meu-prato-api
npx wrangler login
npx wrangler d1 create meuprato-db        # copie o database_id para o wrangler.toml
npx wrangler d1 execute meuprato-db --remote --file=schema.sql
npx wrangler deploy                        # mostra o endereço https://meuprato-api.SEU-NOME.workers.dev
```
Se o login de senha der erro de "CPU time" no plano grátis, baixe `PBKDF2_ITER` em wrangler.toml (ex.: 30000) e rode `npx wrangler deploy` de novo.
