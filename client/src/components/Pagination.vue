<template>
    <nav aria-label="Page navigation example" class="navigation">
        <ul class="pagination">
            <li class="page-item" style="border-top-left-radius: 4px; border-bottom-left-radius: 4px; ">
                <button type="button" @click="paginationStore.indexPrevPage()" class="page-link">
                    Previous
                </button>
            </li>
            <li v-for="(page, index) in paginationStore.pagesNumber(this.totalQuantityMovies)"
                class="page-item page-idx-cur">
                <button type="button" @click="paginationStore.indexCurrentPage(index)" class="page-link">
                    {{ page }}
                </button>
            </li>
            <li class="page-item" style="border-top-right-radius: 4px; border-bottom-right-radius: 4px; ">
                <button type="button" @click="paginationStore.indexNextPage()" class="page-link">
                    Next
                </button>
            </li>
        </ul>
    </nav>
</template>
<script>
import { useMediaStore } from '@/stores/media.js';
import { usePaginationStore } from '@/stores/pagination.js';


export default {
    props: ['totalQuantityMovies'],

    setup() {
        const mediaStore = useMediaStore();
        const paginationStore = usePaginationStore();
        return {
            mediaStore,
            paginationStore
        }
    },

    async mounted() {
        const pageIdxCur = document.getElementsByClassName('page-idx-cur');
        pageIdxCur[this.paginationStore.idxCurPage].classList.add('cur-active');
    }
}
</script>
<style lang="scss" scoped>
.pagination,
.page-item {
    display: flex;
    justify-content: center;
    align-items: center;
}

.page-item {
    font-size: 1.6rem;
    background-color: #fff;
    padding: 8px;

    &.cur-active {
        background-color: rgb(4, 88, 214);

        .page-link {

            color: #fff !important;
        }
    }

    &:not(.cur-active):hover {
        background-color: #ddd;
    }
}

.page-link {
    width: 100%;
    padding: 0;
    margin: 0;
    background-color: transparent;
    box-shadow: none;
    text-align: center;
    font-size: 1.3rem;
}

@media only screen and (max-width: 739px) {
    .page-item {
        padding: 3px 4px;
    }

    .page-link {
        font-size: 1rem;
    }
}
</style>