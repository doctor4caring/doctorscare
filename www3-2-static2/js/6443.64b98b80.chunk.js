"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6443],{45793:(e,l,s)=>{s.d(l,{Z:()=>a});var i=s(29086);const a=async e=>{try{const l=await i.Z.post("/digitalOcean/post",e);return null===l||void 0===l?void 0:l.data}catch(l){return l}}},46443:(e,l,s)=>{s.r(l),s.d(l,{default:()=>_});var i=s(72791),a=s(95070),o=s(47022),d=s(89743),n=s(2677),t=s(36638),r=s(43360),c=s(9897),v=s(84373),m=s(76421),u=s(57689),f=s(11087),x=s(3810),h=s(83086),g=s(59434),j=s(72426),N=s.n(j),b=s(76053),p=s(78820),y=s(39126),I=s(56355),W=s(23853),U=s(73683),w=s(48922),C=s(45793),D=s(80184);const _=function(){const e=(0,u.TH)(),l=(0,u.UO)(),s=(0,i.useRef)(null),j=(0,i.useRef)(null),{user:_}=(0,g.v9)((e=>e.auth)),[k,Z]=(0,i.useState)(""),[E,P]=(0,i.useState)(null),[F,S]=(0,i.useState)(!1),[T,B]=(0,i.useState)(null),[R,M]=(0,i.useState)(null),Y=(0,g.I0)(),{inboxId:z,allMessages:O}=(0,g.v9)((e=>null===e||void 0===e?void 0:e.chat)),{staffData:A}=null===e||void 0===e?void 0:e.state,L=null===_||void 0===_?void 0:_.userId;(0,i.useEffect)((()=>(w.W&&(null===w.W||void 0===w.W||w.W.on("connect",(()=>{console.log("signal1",null===w.W||void 0===w.W?void 0:w.W.connected)})),null===w.W||void 0===w.W||w.W.emit("connectToUserRoom",{userId:L},(()=>{console.log("signal2",null===w.W||void 0===w.W?void 0:w.W.connected)})),null!==w.W&&void 0!==w.W&&w.W.connected||null===w.W||void 0===w.W||w.W.on("reconnect",(()=>{console.log("reconnect",null===w.W||void 0===w.W?void 0:w.W.connected)})),null!==w.W&&void 0!==w.W&&w.W.connected&&console.log("refttytfconnect",null===w.W||void 0===w.W?void 0:w.W.connected),w.W.on("disconnect",(()=>{console.log("Disconnected")}))),()=>{w.W.off("connect"),w.W.off("connected"),w.W.off("disconnect"),w.W.off("messageData")})),[A,w.W]),(0,i.useEffect)((()=>{const e=e=>{if(null!==e&&void 0!==e&&e.data){var l;const s=null===e||void 0===e||null===(l=e.data)||void 0===l?void 0:l.data,i=JSON.parse(s),a={createdDate:(0,U.oA)(new Date),file:null!==i&&void 0!==i&&i.file?null===i||void 0===i?void 0:i.file:null,fileUrl:null!==i&&void 0!==i&&i.fileUrl?null===i||void 0===i?void 0:i.fileUrl:null,fromUserId:null===i||void 0===i?void 0:i.fromUserId,fromUserName:null!==i&&void 0!==i&&i.fromUserName?null===i||void 0===i?void 0:i.fromUserName:null!==A&&void 0!==A&&A.name?null===A||void 0===A?void 0:A.name:null,image:null!==i&&void 0!==i&&i.image?null===i||void 0===i?void 0:i.image:null,imageUrl:null!==i&&void 0!==i&&i.imageUrl?null===i||void 0===i?void 0:i.imageUrl:null,inboxId:null===i||void 0===i?void 0:i.inboxId,message:null===i||void 0===i?void 0:i.message,messageId:null!==i&&void 0!==i&&i.messageId?null===i||void 0===i?void 0:i.messageId:null,toUserId:null===i||void 0===i?void 0:i.toUserId,toUserName:null!==i&&void 0!==i&&i.toUserName?null===i||void 0===i?void 0:i.toUserName:null};Y((0,h.FT)(a))}};return null!==w.W&&void 0!==w.W&&w.W.connected&&w.W.on("messageData",e),()=>{w.W.off("messageData",e)}}),[w.W,z]),(0,i.useEffect)((()=>{const e={fromUserId:null===_||void 0===_?void 0:_.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId)};Y((0,h.Zm)(e))}),[Y,null===_||void 0===_?void 0:_.userId,null===l||void 0===l?void 0:l.staffId]);const H=e=>{w.W.emit("sendMessage",{userIds:[{id:+(null===l||void 0===l?void 0:l.staffId)}],data:JSON.stringify(null===e||void 0===e?void 0:e.data)})},G=e=>{var s,i;P(null===e||void 0===e||null===(s=e.data)||void 0===s?void 0:s.inboxId);const a={inboxId:null===e||void 0===e||null===(i=e.data)||void 0===i?void 0:i.inboxId,fromUserId:null===_||void 0===_?void 0:_.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId),message:k||"",file:(null===R||void 0===R?void 0:R.keyName)||"",fileUrl:(null===R||void 0===R?void 0:R.baseUrl)||"",isChat:!0};Y((0,h.bG)({finalData:a,moveToNext:H}))},J=e=>{if(z||E){const e={inboxId:(null===z||void 0===z?void 0:z.inboxId)||E,fromUserId:null===_||void 0===_?void 0:_.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId),message:k||"",file:(null===R||void 0===R?void 0:R.keyName)||"",fileUrl:(null===R||void 0===R?void 0:R.baseUrl)||"",isChat:!0};Y((0,h.bG)({finalData:e,moveToNext:H}))}else{const e={fromUserId:null===_||void 0===_?void 0:_.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId)};Y((0,h.$p)({finalData:e,movetoNext:G}))}Z(""),B(null),M(null)};(0,i.useEffect)((()=>{if(null!==A&&void 0!==A&&A.inboxId){const e={inboxId:null!==A&&void 0!==A&&A.inboxId?null===A||void 0===A?void 0:A.inboxId:0,fromUserId:L,toUserId:null===A||void 0===A?void 0:A.userId};Y((0,h.SO)(e))}}),[Y,A]);const K=e=>{32===e.which&&0===j.current.selectionStart&&e.preventDefault(),"Enter"===e.key&&(""!==k.trim()||null!==R&&void 0!==R&&R.keyName)&&J()};return(0,i.useEffect)((()=>{var e;null===(e=s.current)||void 0===e||e.scrollIntoView({behavior:"smooth"})}),[O]),(0,i.useEffect)((()=>{const e=j.current;return e&&e.addEventListener("keydown",K),()=>{e&&e.removeEventListener("keydown",K)}}),[]),(0,D.jsxs)(D.Fragment,{children:[(0,D.jsx)("nav",{"aria-label":"breadcrumb",children:(0,D.jsxs)("ol",{className:"breadcrumb",children:[(0,D.jsx)("li",{className:"breadcrumb-item",children:(0,D.jsx)(f.rU,{to:{pathname:x.m.STAFF},className:"text-decoration-none fs-5",style:{color:"#999999"},children:"Staff"})}),(0,D.jsx)(v.hjJ,{className:"ms-2 mt-2"}),(0,D.jsx)("li",{className:"breadcrumb-item active fs-5","aria-current":"page",style:{color:"#000071"},children:"Chat"})]})}),(0,D.jsx)("div",{className:"Staff-Chat-MainClass",children:(0,D.jsx)(a.Z,{className:"h-100 ",children:(0,D.jsx)(a.Z.Body,{className:"py-0 px-0",children:(0,D.jsx)(a.Z.Title,{className:"mb-0",children:(0,D.jsx)(o.Z,{fluid:!0,className:"",children:(0,D.jsx)(d.Z,{children:(0,D.jsxs)(n.Z,{xl:12,lg:10,md:12,className:"px-0 chatContent",style:{boxShadow:"0 0 8px #C3C3C3"},children:[(0,D.jsx)("div",{className:"d-flex justify-content-between mobileFlex_Col py-2 border-bottom px-4 ",children:(0,D.jsx)("div",{className:"d-flex justify-content-center align-items-center chatActive mb-sm-0 mb-3",children:(0,D.jsxs)("div",{className:"d-flex align-items-center py-0",children:[(0,D.jsx)("span",{children:(0,D.jsx)("img",{className:"rounded-circle",width:50,src:null!==A&&void 0!==A&&A.imageUrl?null===A||void 0===A?void 0:A.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===A||void 0===A?void 0:A.name),"&background=000071&color=fff"),alt:"UserImage"})}),(0,D.jsx)("h5",{className:"fw-semibold mb-0 ms-3 mobileTextHeading",children:null===A||void 0===A?void 0:A.name})]})})}),(0,D.jsxs)("div",{children:[(0,D.jsx)("div",{className:"div-fixed-height",style:{background:"#FBFBFB"},children:O.length>0?null===O||void 0===O?void 0:O.map(((e,l)=>{var i,a,o,t,r,v,m,u,f,x,h;let g=N()(N().utc(null===e||void 0===e?void 0:e.createdDate).toDate()).local(!0).format("h:mm a");return(0,D.jsxs)(D.Fragment,{children:[(0,D.jsx)("div",{className:"d-flex flex-column h-100 px-4 py-3 chatBox",children:(0,D.jsxs)("div",{children:[(null===O||void 0===O||null===(i=O[l-1])||void 0===i||null===(a=i.createdDate)||void 0===a||null===(o=a.split("T"))||void 0===o?void 0:o[0])!==(null===e||void 0===e||null===(t=e.createdDate)||void 0===t||null===(r=t.split("T"))||void 0===r?void 0:r[0])&&(0,D.jsx)("div",{className:"text-center rounded-pill mx-auto chatSpan bg-white",children:N()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")===N()(new Date).format("DD-MM-YYYY")?"Today":N()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")}),(0,D.jsx)("div",{children:(0,D.jsx)(d.Z,{children:(null===e||void 0===e?void 0:e.fromUserId)!==(null===_||void 0===_?void 0:_.userId)?(0,D.jsx)(n.Z,{lg:8,md:6,children:(0,D.jsxs)("div",{className:"chatMessage_left d-flex justify-content-start mobileFlex_Col mb-1",children:[(0,D.jsx)("img",{className:"me-2 mb-2 mb-sm-0 rounded-circle object-fit-cover",width:50,height:50,src:null!==e&&void 0!==e&&e.imageUrl?null===e||void 0===e?void 0:e.imageUrl:"https://ui-avatars.com/api/?name=".concat(null===e||void 0===e?void 0:e.fromUserName,"&background=000071&color=fff"),alt:"UserImage"}),(0,D.jsxs)("div",{className:"w-100",children:[(null===e||void 0===e?void 0:e.file)&&(0,D.jsx)("div",{className:"chat__upload-doc",style:{width:"40%"},children:(0,D.jsxs)("a",{href:null===e||void 0===e?void 0:e.fileUrl,target:"_blank",rel:"noopener noreferrer",className:"text-decoration-none",children:[(0,D.jsxs)("div",{className:"d-flex align-items-center p-2 border-bottom",children:[null!==e&&void 0!==e&&null!==(v=e.file)&&void 0!==v&&v.endsWith(".pdf")?(0,D.jsx)(I.B$y,{size:22,color:"#BC0613"}):(0,D.jsx)(y.jnY,{size:22,color:"#000071"}),(0,D.jsx)("label",{className:"chat__upload_text px-2 fw-bold",children:null===e||void 0===e?void 0:e.file})]}),(0,D.jsx)("img",{className:"rounded\n                                                        ".concat(null!==e&&void 0!==e&&null!==(m=e.file)&&void 0!==m&&m.endsWith(".pdf")?"object-fit-contain":"object-fit-cover"),width:"100%",height:"76%",src:null!==e&&void 0!==e&&null!==(u=e.file)&&void 0!==u&&u.endsWith(".pdf")?c.Z.PDF_DOC:null===e||void 0===e?void 0:e.fileUrl,alt:"doc"})]})}),(null===e||void 0===e?void 0:e.message)&&(0,D.jsx)("div",{className:"messageSpan",children:null===e||void 0===e?void 0:e.message}),g&&(0,D.jsx)("div",{className:"chatTime",children:g})]})]})}):(0,D.jsxs)(n.Z,{lg:4,md:6,className:"chatMessage_right text-white d-flex flex-column align-items-end justify-content-end w-100",children:[(null===e||void 0===e?void 0:e.file)&&(0,D.jsx)("div",{className:"chat__upload-doc",children:(0,D.jsxs)("a",{href:null===e||void 0===e?void 0:e.fileUrl,target:"_blank",rel:"noopener noreferrer",className:"text-decoration-none",children:[(0,D.jsxs)("div",{className:"d-flex align-items-center p-2 border-bottom",children:[null!==e&&void 0!==e&&null!==(f=e.file)&&void 0!==f&&f.endsWith(".pdf")?(0,D.jsx)(I.B$y,{size:22,color:"#BC0613"}):(0,D.jsx)(y.jnY,{size:22,color:"#000071"}),(0,D.jsx)("label",{className:"chat__upload_text px-2 fw-bold",children:null===e||void 0===e?void 0:e.file})]}),(0,D.jsx)("img",{className:"rounded\n                                                        ".concat(null!==e&&void 0!==e&&null!==(x=e.file)&&void 0!==x&&x.endsWith(".pdf")?"object-fit-contain":"object-fit-cover"),width:"100%",height:"76%",src:null!==e&&void 0!==e&&null!==(h=e.file)&&void 0!==h&&h.endsWith(".pdf")?c.Z.PDF_DOC:null===e||void 0===e?void 0:e.fileUrl,alt:"doc"})]})}),(null===e||void 0===e?void 0:e.message)&&(0,D.jsx)("span",{className:"mb-1 mt-3 mobile_margin sender-message",children:null===e||void 0===e?void 0:e.message}),g&&(0,D.jsx)("div",{className:"chatTime align-self-end",children:g})]})})})]})}),(0,D.jsx)("div",{ref:s})]})})):(0,D.jsx)("div",{className:"d-flex justify-content-center align-items-center",style:{height:"50vh"},children:(0,D.jsxs)("h5",{className:"mb-0 text-center text-black-50",children:["Welcome to our chat system",(0,D.jsx)("br",{}),"Please feel free to start typing your message"]})})}),(0,D.jsxs)("div",{className:"border-top",children:[(0,D.jsxs)("div",{className:"d-flex justify-content-between align-items-center px-4",children:[(0,D.jsxs)("div",{className:"d-flex justify-content-center align-items-center position-relative",children:[(0,D.jsx)(I.sr,{size:28,color:F?"#000071":"#A8A8A8",className:"text-cursor-pointer",onClick:()=>S((e=>!e))}),F&&(0,D.jsx)(m.ZP,{lazyLoadEmojis:!0,onEmojiClick:e=>{Z((l=>l+(null===e||void 0===e?void 0:e.emoji))),S(!1)},className:"position-absolute",style:{top:"-26.8rem",left:0}}),(0,D.jsx)("div",{className:"mx-3",children:(0,D.jsx)("label",{htmlFor:"file-upload",className:"text-center",children:(0,D.jsx)(W.UH,{size:26,color:"#A8A8A8",className:"text-cursor-pointer"})})}),(0,D.jsx)("input",{size:"small",type:"file",id:"file-upload",name:"file-upload",accept:"image/png, image/jpeg, application/pdf",onChange:e=>{(async e=>{let l=e.target.files[0];if(B(l),l){const e=l.name.lastIndexOf("."),s=l.name.slice(0,e),i=l.name.slice(e+1,l.name.length);if("pdf"===i.toLowerCase()){const e=new FileReader;e.onload=async e=>{const l=e.target.result,a={name:s,base64:l.split(",")[1],fileExtension:"".concat(i)};(0,C.Z)(a).then((e=>{null!==e&&void 0!==e&&e.keyName?(M(e),(0,U.P_)("File uploaded.",!0)):(0,U.P_)("File too large. Max size is 500KB.",!1)}))},e.onerror=e=>{},e.readAsDataURL(l)}else(0,U.ZP)(l).then((e=>{const l={name:s,base64:e,fileExtension:"".concat(i)};(0,C.Z)(l).then((e=>{null!==e&&void 0!==e&&e.keyName?(M(e),(0,U.P_)("File uploaded.",!0)):(0,U.P_)("File too large. Max size is 500KB.",!1)}))}))}})(e)},className:"upload-file"})]}),(0,D.jsx)("div",{className:"w-100",children:(0,D.jsxs)(t.Z.Group,{className:"position-relative my-3 w-100",children:[(0,D.jsx)(t.Z.Control,{as:"textarea",rows:1,className:"padding rounded-pill",placeholder:"Type a message here\u2026",value:k,onChange:e=>Z(e.target.value),ref:j,onKeyDown:K,style:{resize:"none"}}),(0,D.jsx)(r.Z,{className:"sendIcon rounded-circle",onClick:J,disabled:""===k.trim()&&!(null!==R&&void 0!==R&&R.keyName),children:(0,D.jsx)("img",{src:c.Z.SEND_ICON,alt:"messageIcon"})})]})})]}),(null===T||void 0===T?void 0:T.name)&&(0,D.jsxs)("div",{className:"d-flex align-items-center pb-2",style:{marginLeft:"7.5rem"},children:[(0,D.jsx)(b.hF6,{size:25,style:{color:"#000071"}}),(0,D.jsx)("h6",{className:"file-name mb-0 ms-2",children:null===T||void 0===T?void 0:T.name}),(0,D.jsx)("span",{className:"mx-3 text-cursor-pointer",children:(0,D.jsx)(p.oHP,{size:18,onClick:()=>{B(null),M(null),document.getElementById("file-upload").value=null}})})]})]})]})]})})})})})})})]})}},95070:(e,l,s)=>{s.d(l,{Z:()=>Z});var i=s(41418),a=s.n(i),o=s(72791),d=s(10162),n=s(80184);const t=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o="div",...t}=e;return i=(0,d.vE)(i,"card-body"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));t.displayName="CardBody";const r=t,c=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o="div",...t}=e;return i=(0,d.vE)(i,"card-footer"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));c.displayName="CardFooter";const v=c;var m=s(96040);const u=o.forwardRef(((e,l)=>{let{bsPrefix:s,className:i,as:t="div",...r}=e;const c=(0,d.vE)(s,"card-header"),v=(0,o.useMemo)((()=>({cardHeaderBsPrefix:c})),[c]);return(0,n.jsx)(m.Z.Provider,{value:v,children:(0,n.jsx)(t,{ref:l,...r,className:a()(i,c)})})}));u.displayName="CardHeader";const f=u,x=o.forwardRef(((e,l)=>{let{bsPrefix:s,className:i,variant:o,as:t="img",...r}=e;const c=(0,d.vE)(s,"card-img");return(0,n.jsx)(t,{ref:l,className:a()(o?"".concat(c,"-").concat(o):c,i),...r})}));x.displayName="CardImg";const h=x,g=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o="div",...t}=e;return i=(0,d.vE)(i,"card-img-overlay"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));g.displayName="CardImgOverlay";const j=g,N=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o="a",...t}=e;return i=(0,d.vE)(i,"card-link"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));N.displayName="CardLink";const b=N;var p=s(27472);const y=(0,p.Z)("h6"),I=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o=y,...t}=e;return i=(0,d.vE)(i,"card-subtitle"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));I.displayName="CardSubtitle";const W=I,U=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o="p",...t}=e;return i=(0,d.vE)(i,"card-text"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));U.displayName="CardText";const w=U,C=(0,p.Z)("h5"),D=o.forwardRef(((e,l)=>{let{className:s,bsPrefix:i,as:o=C,...t}=e;return i=(0,d.vE)(i,"card-title"),(0,n.jsx)(o,{ref:l,className:a()(s,i),...t})}));D.displayName="CardTitle";const _=D,k=o.forwardRef(((e,l)=>{let{bsPrefix:s,className:i,bg:o,text:t,border:c,body:v=!1,children:m,as:u="div",...f}=e;const x=(0,d.vE)(s,"card");return(0,n.jsx)(u,{ref:l,...f,className:a()(i,x,o&&"bg-".concat(o),t&&"text-".concat(t),c&&"border-".concat(c)),children:v?(0,n.jsx)(r,{children:m}):m})}));k.displayName="Card";const Z=Object.assign(k,{Img:h,Title:_,Subtitle:W,Body:r,Link:b,Text:w,Header:f,Footer:v,ImgOverlay:j})}}]);
//# sourceMappingURL=6443.64b98b80.chunk.js.map