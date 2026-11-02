# Meu Prato API (Cloudflare Workers + D1)

Sistema isolado: só do Meu Prato. Worker `meuprato-api`, banco `meuprato-db`. Não usa nada de outros sistemas (GesCon etc.).

## Publicar
O banco `meuprato-db` e as tabelas já foram criados na conta Cloudflare. Falta só publicar o Worker:
```
cd meu-prato-api
npx wrangler login
npx wrangler deploy                        # mostra o endereço https://meuprato-api.SEU-NOME.workers.dev
```
Se o login de senha der erro de "CPU time" no plano grátis, baixe `PBKDF2_ITER` em wrangler.toml (ex.: 30000) e rode `npx wrangler deploy` de novo.
