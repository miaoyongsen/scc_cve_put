<template><main><h2>SCC CVE</h2><p>请输入服务端设置的访问令牌</p><input v-model="value" type="password" autocomplete="off"/><button @click="enter">进入</button></main></template>
<script setup>
import {ref} from 'vue'
import {useRouter} from 'vue-router'
const value=ref('')
const router=useRouter()
function enter(){if(value.value){localStorage.setItem('token',value.value);router.push('/vulnerabilities')}}
</script>
<style scoped>main{max-width:500px;margin:20vh auto;text-align:center}input,button{padding:10px;margin:8px}</style>
