import { createRouter, createWebHistory } from 'vue-router';

import Header from '../components/Header.vue';
import Footer from '../components/Footer.vue';

import HomeView from '../views/HomeView.vue';
import Login from '../views/Login.vue';
import Movies from '../views/Movies.vue';
import Series from '../views/Series.vue';
import Membership from '../views/Membership.vue';
import EditMedia from '../views/EditMedia.vue';
import CreateMedia from '../views/CreateMedia.vue';
import Trash from '../views/Trash.vue';
import MembershipTrash from '../views/MembershipTrash.vue';
import DetailFavorites from '../views/DetailFavorites.vue';
import DetailReviews from '../views/DetailReviews.vue';

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      components: {
        default: HomeView,
        Header,
        Footer
      }
    },
    {
      path: '/admin/auth',
      name: 'auth',
      component: Login
    },
    {
      path: '/admin/movies',
      name: 'movies',
      components: {
        default: Movies,
        Header,
        Footer
      }
    },
    {
      path: '/admin/series',
      name: 'series',
      components: {
        default: Series,
        Header,
        Footer
      }
    },
    {
      path: '/admin/media/edit/:id',
      name: 'edit',
      props: true,
      components: {
        default: EditMedia,
        Header,
        Footer
      }
    },
    {
      path: '/admin/media/create',
      name: 'create',
      components: {
        default: CreateMedia,
        Header,
        Footer
      }
    },
    {
      path: '/admin/member',
      name: 'member',
      components: {
        default: Membership,
        Header,
        Footer
      }
    },
    {
      path: '/admin/media/recycle-bin',
      name: 'recycle',
      components: {
        default: Trash,
        Header,
        Footer
      }
    },
    {
      path: '/admin/member/recycle-bin',
      name: 'deleted',
      components: {
        default: MembershipTrash,
        Header,
        Footer
      }
    },
    {
      path: '/admin/member/:id/favorites',
      name: 'favorites',
      components: {
        default: DetailFavorites,
        Header,
        Footer
      }
    },
    {
      path: '/admin/member/:id/reviews',
      name: 'reviews',
      components: {
        default: DetailReviews,
        Header,
        Footer
      }
    }
  ]
})

router.beforeEach(async (to, from, next) => {
  const id = JSON.parse(sessionStorage.getItem('ad')) || null;
  if (id === null && to.name !== 'auth') {
    next({ name: 'auth' });
  }
  else if (id !== null && id.isLoggedin === true && to.name === 'auth') {
    next({ name: 'home' });
  }
  else {
    next();
  }
})

export default router
