"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6443],{45793:(e,l,i)=>{i.d(l,{Z:()=>n});var o=i(29086);const n=async e=>{try{const l=await o.Z.post("/digitalOcean/post",e);return null===l||void 0===l?void 0:l.data}catch(l){return l}}},46443:(e,l,i)=>{i.r(l),i.d(l,{default:()=>C});var o=i(72791),n=i(95070),s=i(47022),d=i(89743),a=i(2677),t=i(36638),c=i(43360),r=i(10857),v=i(84373),m=i(76421),u=i(57689),f=i(11087),x=i(3810),h=i(83086),g=i(59434),j=i(72426),p=i.n(j),b=i(76053),N=i(78820),I=i(39126),y=i(56355),W=i(23853),U=i(73683),D=i(66791),w=i(45793),_=i(80184);const C=function(){const e=(0,u.TH)(),l=(0,u.UO)(),i=(0,o.useRef)(null),j=(0,o.useRef)(null),{user:C}=(0,g.v9)((e=>e.auth)),[k,Z]=(0,o.useState)(""),[F,S]=(0,o.useState)(null),[E,T]=(0,o.useState)(!1),[Y,z]=(0,o.useState)(null),[M,B]=(0,o.useState)(null),A=(0,g.I0)(),{inboxId:P,allMessages:O}=(0,g.v9)((e=>null===e||void 0===e?void 0:e.chat)),{staffData:L}=null===e||void 0===e?void 0:e.state,R=null===C||void 0===C?void 0:C.userId;(0,o.useEffect)((()=>(D.W&&(null===D.W||void 0===D.W||D.W.on("connect",(()=>{console.log("signal1",null===D.W||void 0===D.W?void 0:D.W.connected)})),null===D.W||void 0===D.W||D.W.emit("connectToUserRoom",{userId:R},(()=>{console.log("signal2",null===D.W||void 0===D.W?void 0:D.W.connected)})),null!==D.W&&void 0!==D.W&&D.W.connected||null===D.W||void 0===D.W||D.W.on("reconnect",(()=>{console.log("reconnect",null===D.W||void 0===D.W?void 0:D.W.connected)})),null!==D.W&&void 0!==D.W&&D.W.connected&&console.log("refttytfconnect",null===D.W||void 0===D.W?void 0:D.W.connected),D.W.on("disconnect",(()=>{console.log("Disconnected")}))),()=>{D.W.off("connect"),D.W.off("connected"),D.W.off("disconnect"),D.W.off("messageData")})),[L,D.W]),(0,o.useEffect)((()=>{const e=e=>{if(null!==e&&void 0!==e&&e.data){var l;const i=null===e||void 0===e||null===(l=e.data)||void 0===l?void 0:l.data,o=JSON.parse(i),n={createdDate:(0,U.oA)(new Date),file:null!==o&&void 0!==o&&o.file?null===o||void 0===o?void 0:o.file:null,fileUrl:null!==o&&void 0!==o&&o.fileUrl?null===o||void 0===o?void 0:o.fileUrl:null,fromUserId:null===o||void 0===o?void 0:o.fromUserId,fromUserName:null!==o&&void 0!==o&&o.fromUserName?null===o||void 0===o?void 0:o.fromUserName:null!==L&&void 0!==L&&L.name?null===L||void 0===L?void 0:L.name:null,image:null!==o&&void 0!==o&&o.image?null===o||void 0===o?void 0:o.image:null,imageUrl:null!==o&&void 0!==o&&o.imageUrl?null===o||void 0===o?void 0:o.imageUrl:null,inboxId:null===o||void 0===o?void 0:o.inboxId,message:null===o||void 0===o?void 0:o.message,messageId:null!==o&&void 0!==o&&o.messageId?null===o||void 0===o?void 0:o.messageId:null,toUserId:null===o||void 0===o?void 0:o.toUserId,toUserName:null!==o&&void 0!==o&&o.toUserName?null===o||void 0===o?void 0:o.toUserName:null};A((0,h.FT)(n))}};return null!==D.W&&void 0!==D.W&&D.W.connected&&D.W.on("messageData",e),()=>{D.W.off("messageData",e)}}),[D.W,P]),(0,o.useEffect)((()=>{const e={fromUserId:null===C||void 0===C?void 0:C.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId)};A((0,h.Zm)(e))}),[A,null===C||void 0===C?void 0:C.userId,null===l||void 0===l?void 0:l.staffId]);const H=e=>{D.W.emit("sendMessage",{userIds:[{id:+(null===l||void 0===l?void 0:l.staffId)}],data:JSON.stringify(null===e||void 0===e?void 0:e.data)})},G=e=>{var i,o;S(null===e||void 0===e||null===(i=e.data)||void 0===i?void 0:i.inboxId);const n={inboxId:null===e||void 0===e||null===(o=e.data)||void 0===o?void 0:o.inboxId,fromUserId:null===C||void 0===C?void 0:C.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId),message:k||"",file:(null===M||void 0===M?void 0:M.keyName)||"",fileUrl:(null===M||void 0===M?void 0:M.baseUrl)||"",isChat:!0};A((0,h.bG)({finalData:n,moveToNext:H}))},J=e=>{if(P||F){const e={inboxId:(null===P||void 0===P?void 0:P.inboxId)||F,fromUserId:null===C||void 0===C?void 0:C.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId),message:k||"",file:(null===M||void 0===M?void 0:M.keyName)||"",fileUrl:(null===M||void 0===M?void 0:M.baseUrl)||"",isChat:!0};A((0,h.bG)({finalData:e,moveToNext:H}))}else{const e={fromUserId:null===C||void 0===C?void 0:C.userId,toUserId:+(null===l||void 0===l?void 0:l.staffId)};A((0,h.$p)({finalData:e,movetoNext:G}))}Z(""),z(null),B(null)};(0,o.useEffect)((()=>{if(null!==L&&void 0!==L&&L.inboxId){const e={inboxId:null!==L&&void 0!==L&&L.inboxId?null===L||void 0===L?void 0:L.inboxId:0,fromUserId:R,toUserId:null===L||void 0===L?void 0:L.userId};A((0,h.SO)(e))}}),[A,L]);const K=e=>{32===e.which&&0===j.current.selectionStart&&e.preventDefault(),"Enter"===e.key&&(""!==k.trim()||null!==M&&void 0!==M&&M.keyName)&&J()};return(0,o.useEffect)((()=>{var e;null===(e=i.current)||void 0===e||e.scrollIntoView({behavior:"smooth"})}),[O]),(0,o.useEffect)((()=>{const e=j.current;return e&&e.addEventListener("keydown",K),()=>{e&&e.removeEventListener("keydown",K)}}),[]),(0,_.jsxs)(_.Fragment,{children:[(0,_.jsx)("nav",{"aria-label":"breadcrumb",children:(0,_.jsxs)("ol",{className:"breadcrumb",children:[(0,_.jsx)("li",{className:"breadcrumb-item",children:(0,_.jsx)(f.rU,{to:{pathname:x.m.STAFF},className:"text-decoration-none fs-5",style:{color:"#999999"},children:"Staff"})}),(0,_.jsx)(v.hjJ,{className:"ms-2 mt-2"}),(0,_.jsx)("li",{className:"breadcrumb-item active fs-5","aria-current":"page",style:{color:"#000071"},children:"Chat"})]})}),(0,_.jsx)("div",{className:"Staff-Chat-MainClass",children:(0,_.jsx)(n.Z,{className:"h-100 ",children:(0,_.jsx)(n.Z.Body,{className:"py-0 px-0",children:(0,_.jsx)(n.Z.Title,{className:"mb-0",children:(0,_.jsx)(s.Z,{fluid:!0,className:"",children:(0,_.jsx)(d.Z,{children:(0,_.jsxs)(a.Z,{xl:12,lg:10,md:12,className:"px-0 chatContent",style:{boxShadow:"0 0 8px #C3C3C3"},children:[(0,_.jsx)("div",{className:"d-flex justify-content-between mobileFlex_Col py-2 border-bottom px-4 ",children:(0,_.jsx)("div",{className:"d-flex justify-content-center align-items-center chatActive mb-sm-0 mb-3",children:(0,_.jsxs)("div",{className:"d-flex align-items-center py-0",children:[(0,_.jsx)("span",{children:(0,_.jsx)("img",{className:"rounded-circle",width:50,src:null!==L&&void 0!==L&&L.imageUrl?null===L||void 0===L?void 0:L.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===L||void 0===L?void 0:L.name),"&background=000071&color=fff"),alt:"UserImage"})}),(0,_.jsx)("h5",{className:"fw-semibold mb-0 ms-3 mobileTextHeading",children:null===L||void 0===L?void 0:L.name})]})})}),(0,_.jsxs)("div",{children:[(0,_.jsx)("div",{className:"div-fixed-height",style:{background:"#FBFBFB"},children:O.length>0?null===O||void 0===O?void 0:O.map(((e,l)=>{var o,n,s,t,c,v,m,u,f,x,h;let g=p()(p().utc(null===e||void 0===e?void 0:e.createdDate).toDate()).local(!0).format("h:mm a");return(0,_.jsxs)(_.Fragment,{children:[(0,_.jsx)("div",{className:"d-flex flex-column h-100 px-4 py-3 chatBox",children:(0,_.jsxs)("div",{children:[(null===O||void 0===O||null===(o=O[l-1])||void 0===o||null===(n=o.createdDate)||void 0===n||null===(s=n.split("T"))||void 0===s?void 0:s[0])!==(null===e||void 0===e||null===(t=e.createdDate)||void 0===t||null===(c=t.split("T"))||void 0===c?void 0:c[0])&&(0,_.jsx)("div",{className:"text-center rounded-pill mx-auto chatSpan bg-white",children:p()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")===p()(new Date).format("DD-MM-YYYY")?"Today":p()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")}),(0,_.jsx)("div",{children:(0,_.jsx)(d.Z,{children:(null===e||void 0===e?void 0:e.fromUserId)!==(null===C||void 0===C?void 0:C.userId)?(0,_.jsx)(a.Z,{lg:8,md:6,children:(0,_.jsxs)("div",{className:"chatMessage_left d-flex justify-content-start mobileFlex_Col mb-1",children:[(0,_.jsx)("img",{className:"me-2 mb-2 mb-sm-0 rounded-circle object-fit-cover",width:50,height:50,src:null!==e&&void 0!==e&&e.imageUrl?null===e||void 0===e?void 0:e.imageUrl:"https://ui-avatars.com/api/?name=".concat(null===e||void 0===e?void 0:e.fromUserName,"&background=000071&color=fff"),alt:"UserImage"}),(0,_.jsxs)("div",{className:"w-100",children:[(null===e||void 0===e?void 0:e.file)&&(0,_.jsx)("div",{className:"chat__upload-doc",style:{width:"40%"},children:(0,_.jsxs)("a",{href:null===e||void 0===e?void 0:e.fileUrl,target:"_blank",rel:"noopener noreferrer",className:"text-decoration-none",children:[(0,_.jsxs)("div",{className:"d-flex align-items-center p-2 border-bottom",children:[null!==e&&void 0!==e&&null!==(v=e.file)&&void 0!==v&&v.endsWith(".pdf")?(0,_.jsx)(y.B$y,{size:22,color:"#BC0613"}):(0,_.jsx)(I.jnY,{size:22,color:"#000071"}),(0,_.jsx)("label",{className:"chat__upload_text px-2 fw-bold",children:null===e||void 0===e?void 0:e.file})]}),(0,_.jsx)("img",{className:"rounded\n                                                        ".concat(null!==e&&void 0!==e&&null!==(m=e.file)&&void 0!==m&&m.endsWith(".pdf")?"object-fit-contain":"object-fit-cover"),width:"100%",height:"76%",src:null!==e&&void 0!==e&&null!==(u=e.file)&&void 0!==u&&u.endsWith(".pdf")?r.Z.PDF_DOC:null===e||void 0===e?void 0:e.fileUrl,alt:"doc"})]})}),(null===e||void 0===e?void 0:e.message)&&(0,_.jsx)("div",{className:"messageSpan",children:null===e||void 0===e?void 0:e.message}),g&&(0,_.jsx)("div",{className:"chatTime",children:g})]})]})}):(0,_.jsxs)(a.Z,{lg:4,md:6,className:"chatMessage_right text-white d-flex flex-column align-items-end justify-content-end w-100",children:[(null===e||void 0===e?void 0:e.file)&&(0,_.jsx)("div",{className:"chat__upload-doc",children:(0,_.jsxs)("a",{href:null===e||void 0===e?void 0:e.fileUrl,target:"_blank",rel:"noopener noreferrer",className:"text-decoration-none",children:[(0,_.jsxs)("div",{className:"d-flex align-items-center p-2 border-bottom",children:[null!==e&&void 0!==e&&null!==(f=e.file)&&void 0!==f&&f.endsWith(".pdf")?(0,_.jsx)(y.B$y,{size:22,color:"#BC0613"}):(0,_.jsx)(I.jnY,{size:22,color:"#000071"}),(0,_.jsx)("label",{className:"chat__upload_text px-2 fw-bold",children:null===e||void 0===e?void 0:e.file})]}),(0,_.jsx)("img",{className:"rounded\n                                                        ".concat(null!==e&&void 0!==e&&null!==(x=e.file)&&void 0!==x&&x.endsWith(".pdf")?"object-fit-contain":"object-fit-cover"),width:"100%",height:"76%",src:null!==e&&void 0!==e&&null!==(h=e.file)&&void 0!==h&&h.endsWith(".pdf")?r.Z.PDF_DOC:null===e||void 0===e?void 0:e.fileUrl,alt:"doc"})]})}),(null===e||void 0===e?void 0:e.message)&&(0,_.jsx)("span",{className:"mb-1 mt-3 mobile_margin sender-message",children:null===e||void 0===e?void 0:e.message}),g&&(0,_.jsx)("div",{className:"chatTime align-self-end",children:g})]})})})]})}),(0,_.jsx)("div",{ref:i})]})})):(0,_.jsx)("div",{className:"d-flex justify-content-center align-items-center",style:{height:"50vh"},children:(0,_.jsxs)("h5",{className:"mb-0 text-center text-black-50",children:["Welcome to our chat system",(0,_.jsx)("br",{}),"Please feel free to start typing your message"]})})}),(0,_.jsxs)("div",{className:"border-top",children:[(0,_.jsxs)("div",{className:"d-flex justify-content-between align-items-center px-4",children:[(0,_.jsxs)("div",{className:"d-flex justify-content-center align-items-center position-relative",children:[(0,_.jsx)(y.sr,{size:28,color:E?"#000071":"#A8A8A8",className:"text-cursor-pointer",onClick:()=>T((e=>!e))}),E&&(0,_.jsx)(m.ZP,{lazyLoadEmojis:!0,onEmojiClick:e=>{Z((l=>l+(null===e||void 0===e?void 0:e.emoji))),T(!1)},className:"position-absolute",style:{top:"-26.8rem",left:0}}),(0,_.jsx)("div",{className:"mx-3",children:(0,_.jsx)("label",{htmlFor:"file-upload",className:"text-center",children:(0,_.jsx)(W.UH,{size:26,color:"#A8A8A8",className:"text-cursor-pointer"})})}),(0,_.jsx)("input",{size:"small",type:"file",id:"file-upload",name:"file-upload",accept:"image/png, image/jpeg, application/pdf",onChange:e=>{(async e=>{let l=e.target.files[0];if(z(l),l){const e=l.name.lastIndexOf("."),i=l.name.slice(0,e),o=l.name.slice(e+1,l.name.length);if("pdf"===o.toLowerCase()){const e=new FileReader;e.onload=async e=>{const l=e.target.result,n={name:i,base64:l.split(",")[1],fileExtension:"".concat(o)};(0,w.Z)(n).then((e=>{null!==e&&void 0!==e&&e.keyName?(B(e),(0,U.P_)("File uploaded.",!0)):(0,U.P_)("File too large. Max size is 500KB.",!1)}))},e.onerror=e=>{},e.readAsDataURL(l)}else(0,U.ZP)(l).then((e=>{const l={name:i,base64:e,fileExtension:"".concat(o)};(0,w.Z)(l).then((e=>{null!==e&&void 0!==e&&e.keyName?(B(e),(0,U.P_)("File uploaded.",!0)):(0,U.P_)("File too large. Max size is 500KB.",!1)}))}))}})(e)},className:"upload-file"})]}),(0,_.jsx)("div",{className:"w-100",children:(0,_.jsxs)(t.Z.Group,{className:"position-relative my-3 w-100",children:[(0,_.jsx)(t.Z.Control,{as:"textarea",rows:1,className:"padding rounded-pill",placeholder:"Type a message here\u2026",value:k,onChange:e=>Z(e.target.value),ref:j,onKeyDown:K,style:{resize:"none"}}),(0,_.jsx)(c.Z,{className:"sendIcon rounded-circle",onClick:J,disabled:""===k.trim()&&!(null!==M&&void 0!==M&&M.keyName),children:(0,_.jsx)("img",{src:r.Z.SEND_ICON,alt:"messageIcon"})})]})})]}),(null===Y||void 0===Y?void 0:Y.name)&&(0,_.jsxs)("div",{className:"d-flex align-items-center pb-2",style:{marginLeft:"7.5rem"},children:[(0,_.jsx)(b.hF6,{size:25,style:{color:"#000071"}}),(0,_.jsx)("h6",{className:"file-name mb-0 ms-2",children:null===Y||void 0===Y?void 0:Y.name}),(0,_.jsx)("span",{className:"mx-3 text-cursor-pointer",children:(0,_.jsx)(N.oHP,{size:18,onClick:()=>{z(null),B(null),document.getElementById("file-upload").value=null}})})]})]})]})]})})})})})})})]})}}}]);
//# sourceMappingURL=6443.4630f179.chunk.js.map