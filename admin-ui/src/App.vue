<template>
  <router-view name="Header" :key="$route.path" />
  <router-view />
  <router-view name="Footer" />
</template>
<script>
</script>
<style lang="scss"></style>