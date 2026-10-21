import axios from 'axios'
const http=axios.create({baseURL:'/api/v1',timeout:15000})
http.interceptors.request.use(config=>{config.headers.Authorization='Bearer '+(localStorage.getItem('token')||'');return config})
http.interceptors.response.use(r=>r.data,e=>{if(e.response?.status===401){localStorage.removeItem('token');window.location.href='/login'}return Promise.reject(e)})
export const list=(params)=>http.get('/vulnerabilities',{params})
export const detail=(id)=>http.get('/vulnerabilities/'+id)
export const refresh=()=>http.post('/vulnerabilities/refresh')
