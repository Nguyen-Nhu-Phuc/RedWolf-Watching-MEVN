<template>
    <VueAvatar :username="getName" />
</template>
<script>
export default {
    props: ['fullName'],

    computed: {
        getName() {
            const temp = this.removeAccents(this.fullName);
            const name = temp.split(' ');
            return name[name.length - 1];
        }
    },

    methods: {
        removeAccents(str) {
            return str.normalize('NFD')
                .replace(/[\u0300-\u036f]/g, '')
                .replace(/đ/g, 'd').replace(/Đ/g, 'D');
        }
    },
}
</script>
<style lang="scss" scoped></style>