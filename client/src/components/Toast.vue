<template>
    <div class="toast hide" data-delay="5000" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="toast-header p-3">
            <!-- <img src="..." class="rounded mr-2" alt="..."> -->
            <font-awesome-icon :icon="['fas', 'spinner']" />
            <strong class="ml-2 mr-auto text-success">Loading...</strong>
            <!-- <small class="text-muted">just now</small> -->
            <!-- <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Close">
                <span aria-hidden="true">&times;</span>
            </button> -->
        </div>
        <div class="toast-body">
            Info progressing...
        </div>
        <div class="w-100" style="height: 4px; background-color: transparent;">
            <div class="progress"></div>
        </div>
    </div>
</template>
<script>
export default {

}
</script>
<style lang="scss" scoped>
.toast {
    min-width: 270px;
    max-width: calc(270px + 10%);
    border-left: 4px solid green !important;
    background-color: #fff;
    animation: slideInLeft ease .3s, fadeOut linear 4s 1s forwards;

    .toast-body {
        background-color: #eee;
    }
}

.progress {
    background-color: rgb(93, 225, 5);
    width: 100%;
    height: 100%;
    animation: loading linear 3s 1s forwards;
}

@keyframes slideInLeft {
    from {
        opacity: 0;
        transform: translateX(calc(100% + 32px));
    }

    to {
        opacity: 1;
        transform: translateX(0);
    }
}

@keyframes fadeOut {
    to {
        opacity: 0;
    }
}

@keyframes loading {
    to {
        width: 0;
    }
}
</style>