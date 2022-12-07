import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import { defineConfig } from 'vitest/config';

export default defineConfig({
    plugins: [
        wasm(),
        topLevelAwait()
    ],
    optimizeDeps: {
        exclude: [
            "@web3-social/chacha20-poly1305-js-sys"
        ]
    }
})
