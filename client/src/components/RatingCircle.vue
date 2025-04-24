<template>
    <div class="rating"></div>
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

    methods: {
        async handleRatingCircle() {
            // Find al rating items
            const ratings = document.querySelectorAll(".rating");

            // Iterate over all rating items
            ratings.forEach((rating) => {
                // Get content and get score as an int
                const ratingContent = rating.innerHTML;
                const ratingScore = parseInt(ratingContent, 10);

                // Define if the score is good, meh or bad according to its value
                const scoreClass =
                    ratingScore < 40 ? "bad" : ratingScore < 60 ? "meh" : "good";

                // Add score class to the rating
                rating.classList.add(scoreClass);

                // After adding the class, get its color
                const ratingColor = window.getComputedStyle(rating).backgroundColor;

                // Define the background gradient according to the score and color
                const gradient = `background: conic-gradient(${ratingColor} ${ratingScore}%, transparent 0 100%)`;

                // Set the gradient as the rating background
                rating.setAttribute("style", gradient);

                // Wrap the content in a tag to show it above the pseudo element that masks the bar
                rating.innerHTML = `<span style="z-index: 2;">${ratingScore} ${ratingContent.indexOf("%") >= 0 ? "<small>%</small>" : ""
                    }</span>`;
            });
        },
    },

    async mounted() {
        const ratingEle = document.getElementsByClassName('rating')[0]
        ratingEle.innerHTML = this.mediaStore.scoreMediaIntro + ' / 100';
        await this.handleRatingCircle();
    },


}
</script>

<style lang="scss" scoped>
@import '@/assets/styles/ratingCircle.scss';
</style>