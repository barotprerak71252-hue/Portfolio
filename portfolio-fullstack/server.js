require('dotenv').config();
const express=require('express'),mongoose=require('mongoose'),jwt=require('jsonwebtoken'),crypto=require('crypto'),rateLimit=require('express-rate-limit'),path=require('path');
const {MONGODB_URI,JWT_SECRET,ADMIN_PASSWORD,PORT=3000}=process.env;
if(!MONGODB_URI||!JWT_SECRET||!ADMIN_PASSWORD){console.error('Set MONGODB_URI, JWT_SECRET and ADMIN_PASSWORD (see .env.example)');process.exit(1)}
const Message=mongoose.model('Message',new mongoose.Schema({name:String,email:String,message:String,read:{type:Boolean,default:false}},{timestamps:true}));
const Project=mongoose.model('Project',new mongoose.Schema({title:String,description:String,tags:[String],highlights:[String],repoUrl:String,liveUrl:String,badge:{type:String,default:'LEARNING BUILD'},featured:{type:Boolean,default:false},order:{type:Number,default:0}},{timestamps:true}));
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));
const s=(v,n)=>String(v??'').trim().slice(0,n);
const url=v=>/^https?:\/\/\S+$/i.test(v=s(v,300))?v:'';
const list=(v,n)=>(Array.isArray(v)?v:[]).map(x=>s(x,n)).filter(Boolean).slice(0,20);
const h=v=>crypto.createHash('sha256').update(v).digest();
const auth=(q,r,n)=>{try{jwt.verify((q.headers.authorization||'').replace('Bearer ',''),JWT_SECRET);n()}catch{r.status(401).json({error:'unauthorized'})}};
const wrap=f=>(q,r)=>f(q,r).catch(e=>{console.error(e);r.status(500).json({error:'server error'})});
const proj=b=>({title:s(b.title,120),description:s(b.description,1000),tags:list(b.tags,40),highlights:list(b.highlights,160),repoUrl:url(b.repoUrl),liveUrl:url(b.liveUrl),badge:s(b.badge,30)||'LEARNING BUILD',featured:!!b.featured,order:Number(b.order)||0});

// public
app.post('/api/messages',rateLimit({windowMs:3600e3,limit:5,message:{error:'too many messages — try again later'}}),wrap(async(q,r)=>{
  const name=s(q.body.name,100),email=s(q.body.email,200),message=s(q.body.message,3000);
  if(!name||!message||!/^\S+@\S+\.\S+$/.test(email))return r.status(400).json({error:'name, a valid email and a message are required'});
  await Message.create({name,email,message});r.status(201).json({ok:true})}));
app.get('/api/projects',wrap(async(q,r)=>r.json(await Project.find().sort({featured:-1,order:1,createdAt:1}).lean())));

// admin
app.post('/api/admin/login',rateLimit({windowMs:900e3,limit:10,message:{error:'too many attempts'}}),(q,r)=>
  crypto.timingSafeEqual(h(s(q.body.password,200)),h(ADMIN_PASSWORD))?r.json({token:jwt.sign({admin:1},JWT_SECRET,{expiresIn:'12h'})}):r.status(401).json({error:'wrong password'}));
const a=express.Router();a.use(auth);
a.get('/messages',wrap(async(q,r)=>r.json(await Message.find().sort({createdAt:-1}).lean())));
a.patch('/messages/:id',wrap(async(q,r)=>r.json(await Message.findByIdAndUpdate(q.params.id,{read:!!q.body.read},{new:true}))));
a.delete('/messages/:id',wrap(async(q,r)=>{await Message.findByIdAndDelete(q.params.id);r.json({ok:true})}));
a.post('/projects',wrap(async(q,r)=>r.status(201).json(await Project.create(proj(q.body)))));
a.put('/projects/:id',wrap(async(q,r)=>r.json(await Project.findByIdAndUpdate(q.params.id,proj(q.body),{new:true}))));
a.delete('/projects/:id',wrap(async(q,r)=>{await Project.findByIdAndDelete(q.params.id);r.json({ok:true})}));
app.use('/api/admin',a);

app.get('/admin',(q,r)=>r.sendFile(path.join(__dirname,'public','admin.html')));
app.use(express.static(path.join(__dirname,'public')));

const seed=[
{title:'Slotify — Slot Booking REST API',description:'Users register, log in, browse available slots, book them and cancel their own bookings. Every write operation is JWT-protected, double-bookings are blocked, and same-date overlaps are rejected with a 409. Built with Node.js, Express and MongoDB.',tags:['node.js','express','mongodb','mongoose','jwt','bcrypt'],highlights:['jwt auth + bcrypt password hashing','slot crud · book · cancel with ownership rules','double-booking & overlap conflict prevention (409)','/bookings/me — see your own bookings'],featured:true,badge:'FEATURED',order:0},
{title:'Student Records API',description:'A learning build — REST API for managing student records with CRUD, validation and JWT-based auth in Spring Boot.',tags:['java','spring boot','rest','sql'],order:1},
{title:'Containerized Deploy Lab',description:'A learning build — packaging a Spring Boot service into lean Docker images and orchestrating it with docker-compose.',tags:['docker','docker-compose','spring boot'],order:2}];
mongoose.connect(MONGODB_URI).then(async()=>{
  if(!await Project.countDocuments())await Project.insertMany(seed);
  app.listen(PORT,()=>console.log('running on :'+PORT));
}).catch(e=>{console.error('MongoDB connection failed:',e.message);process.exit(1)});
