import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '@/views/HomeView.vue';
import Movies from '@/views/Movies.vue';
import Series from '@/views/Series.vue';
import Search from '@/views/Search.vue';
import DetailMedia from '@/views/DetailMedia.vue';
import Watching from '@/views/Watching.vue';
import Favorites from '@/views/Favorites.vue';
import Review from '@/views/ReviewPage.vue';
import ChangePassword from '@/views/ChangePassword.vue';


const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView
    },
    {
      path: '/movies',
      name: 'movies',
      component: Movies
    },
    {
      path: '/tv-series',
      name: 'series',
      component: Series
    },
    {
      path: '/search',
      name: 'search',
      component: Search
    },
    {
      path: '/info/media/:id',
      name: 'detail',
      props: true,
      component: DetailMedia
    },
    {
      path: '/watching/media/:id',
      name: 'watching',
      props: true,
      component: Watching
    },
    {
      path: '/my-favorites',
      name: 'favorites',
      component: Favorites
    },
    {
      path: '/review',
      name: 'review',
      component: Review
    },
    {
      path: '/password',
      name: 'password',
      component: ChangePassword
    }
  ],
  scrollBehavior() {
    document.getElementById('app').scrollIntoView({ behavior: 'instant' });
  }
})

export default router
