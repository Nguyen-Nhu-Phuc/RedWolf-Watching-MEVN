import { createApp } from 'vue';
import { createPinia } from 'pinia'
import piniaPluginPersistedState from "pinia-plugin-persistedstate"
import 'bootstrap'
import 'bootstrap/dist/css/bootstrap.min.css'
import 'bootstrap/dist/js/bootstrap.min.js'
import VueAvatar from "@webzlodimir/vue-avatar";
import "@webzlodimir/vue-avatar/dist/style.css";
import { library } from '@fortawesome/fontawesome-svg-core'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
import { fas } from '@fortawesome/free-solid-svg-icons'
import { fab } from '@fortawesome/free-brands-svg-icons'
import { far } from '@fortawesome/free-regular-svg-icons'
import { dom } from '@fortawesome/fontawesome-svg-core'

import App from './App.vue'
import router from './router'



library.add(fas);
library.add(fab);
library.add(far);
dom.watch();


const app = createApp(App)
const pinia = createPinia();
pinia.use(piniaPluginPersistedState);

app.component('font-awesome-icon', FontAwesomeIcon);
app.component('VueAvatar', VueAvatar);
app.use(pinia)
app.use(router)

app.mount('#app')
