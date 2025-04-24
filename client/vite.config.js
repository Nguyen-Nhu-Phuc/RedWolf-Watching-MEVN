import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'
const url_local = 'https://redwolf-cine-server.onrender.com';

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [vue()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    css: {
        preprocessorOptions: {
            scss: {
                additionalData: `@import "@/assets/styles/globalStyle.scss";`
            }
        }
    },
    // server: {
    //     port: 8000,
    //     proxy: {
    //         '/media': {
    //             target: url_local,
    //             changeOrigin: true,
    //         },
    //         '/users': {
    //             target: url_local,
    //             changeOrigin: true,
    //         },
    //         '/favorites': {
    //             target: url_local,
    //             changeOrigin: true,
    //         },
    //         '/reviews': {
    //             target: url_local,
    //             changeOrigin: true,
    //         }
    //     },
    // },
})
