<template>
    <!--Carousel Wrapper-->
    <div id="carousel-img-media" class="carousel slide carousel-fade w-100 h-100" data-ride="carousel"
        v-if="mediaStore.media">
        <!--Indicators-->
        <ol class="carousel-indicators">
            <li v-for="(img, index) in mediaStore.media.posters.slice(2)" :key="index" data-target="#carousel-img-media"
                :data-slide-to="index" @click="activate(index)" class="btn-slide"
                :class="{ active: active_curUrl == index }" :data-idx="index">
            </li>
        </ol>
        <!--/.Indicators-->

        <!--Slides-->
        <div class="carousel-inner" role="listbox">
            <div class="carousel-item" v-for="(img, index) in mediaStore.media.posters.slice(2)" :key="index">
                <img class="d-block w-100 carousel-item-slide" :src="img" alt="slide item" />
            </div>
        </div>
        <!--/.Slides-->

        <!--Controls-->
        <button class="carousel-control-prev" style="position: absolute;" data-target="#carousel-img-media" type="button"
            data-slide="prev">
            <span class="carousel-control-prev-icon" aria-hidden="true"></span>
            <span class="sr-only">Previous</span>
        </button>
        <button class="carousel-control-next" style="position: absolute;" data-target="#carousel-img-media" type="button"
            data-slide="next">
            <span class="carousel-control-next-icon" aria-hidden="true"></span>
            <span class="sr-only">Next</span>
        </button>
        <!--/.Controls-->
    </div>
    <!--/.Carousel Wrapper-->
</template>

<script>
import { useMediaStore } from '@/stores/media.js';

export default {
    setup() {
        const mediaStore = useMediaStore();
        return {
            mediaStore
        }
    },

    data() {
        return {
            active_curUrl: 0,
        }
    },

    methods: {
        activate: function (el) {
            this.active_curUrl = el;
        }
    },

    async mounted() {
        var btnSlideElements = document.getElementsByClassName('btn-slide');
        for (let index = 0; index < btnSlideElements.length; index++) {
            const element = btnSlideElements[index].classList.contains('active')
            if (element) {
                document.getElementsByClassName('carousel-item')[index].classList.add('active');
            }
        }
    }
}
</script>

<style lang="scss" scoped>
.carousel-item {
    height: 100%;
    width: 100%;

    .carousel-item-slide {
        height: 600px;
        object-fit: cover;
    }
}

@media only screen and (min-width: 740px) and (max-width: 1023px) {
    .carousel-item {
        height: 100%;
        width: 100%;

        .carousel-item-slide {
            height: 400px;
            object-fit: cover;
        }
    }
}

@media only screen and (max-width: 739px) {
    .carousel-inner {
        height: 280px;
    }

    .carousel-item {
        .carousel-item-slide {
            height: 280px;
            object-fit: cover;
        }
    }
}
</style>