FROM denoland/deno:2.2.0

WORKDIR /app

COPY main.ts .

EXPOSE 8000

CMD ["deno", "run",
"--allow-net",
"--allow-env",
"--allow-read",
"main.ts"]
