const QUANTITY_FILM_PAGE = 12;
import { defineStore } from 'pinia';

export const usePaginationStore = defineStore('pagination', {
    state: () => {
        return {
            idxCurPage: 0,
            pagesNum: 0
        }
    },

    actions: {
        pagesNumber(totalQuantityMovies) {
            this.pagesNum = Math.ceil(totalQuantityMovies / QUANTITY_FILM_PAGE);
            return this.pagesNum;
        },

        indexFirstFilmOfPage(idxPage) {
            return idxPage * QUANTITY_FILM_PAGE;
        },

        indexLastFilmOfPage(idxPage) {
            return idxPage * QUANTITY_FILM_PAGE + (QUANTITY_FILM_PAGE - 1);
        },

        indexCurrentPage(idxPage) {
            this.idxCurPage = idxPage;
        },

        indexPrevPage() {
            if (this.idxCurPage > 0) {
                this.idxCurPage = this.idxCurPage - 1;
            }
        },

        indexNextPage() {
            if (this.idxCurPage < (this.pagesNum - 1)) {
                this.idxCurPage = this.idxCurPage + 1;
            }
        },
    },
});
