"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3083],{78074:(e,s,a)=>{a.r(s),a.d(s,{default:()=>b});var l=a(72791),i=a(95070),n=a(47022),d=a(89743),r=a(2677),t=a(36638),o=a(1444),c=a(43360),m=a(7692),v=a(39126),u=a(4053),x=a(83086),f=a(59434),h=a(72426),N=a.n(h),g=a(73683),j=a(66791),p=a(80184);const b=()=>{const e=(0,f.I0)(),s=(0,l.useRef)(null),a=(0,l.useRef)(null),[h,b]=(0,l.useState)(""),[y,I]=(0,l.useState)(),{user:C}=(0,f.v9)((e=>e.auth)),{allInboxList:w,allMessages:W}=(0,f.v9)((e=>null===e||void 0===e?void 0:e.chat)),U=null===C||void 0===C?void 0:C.userId;(0,l.useEffect)((()=>{j.W&&(null===j.W||void 0===j.W||j.W.on("connect",(()=>{console.log("signal1",null===j.W||void 0===j.W?void 0:j.W.connected)})),null===j.W||void 0===j.W||j.W.emit("connectToUserRoom",{userId:U},(()=>{console.log("signal2",null===j.W||void 0===j.W?void 0:j.W.connected)})),!1===(null===j.W||void 0===j.W?void 0:j.W.connected)&&(null===j.W||void 0===j.W||j.W.on("reconnect",(()=>{console.log("reconnect",null===j.W||void 0===j.W?void 0:j.W.connected)}))),!0===(null===j.W||void 0===j.W?void 0:j.W.connected)&&console.log("refttytfconnect",null===j.W||void 0===j.W?void 0:j.W.connected))}),[U,j.W]),(0,l.useEffect)((()=>{!0===(null===j.W||void 0===j.W?void 0:j.W.connected)&&(null===j.W||void 0===j.W||j.W.on("messageData",(s=>{if(null!==s&&void 0!==s&&s.data){var a;const l=null===s||void 0===s||null===(a=s.data)||void 0===a?void 0:a.data,i=JSON.parse(l),n={createdDate:(0,g.oA)(new Date),file:null!==i&&void 0!==i&&i.file?null===i||void 0===i?void 0:i.file:null,fileUrl:null!==i&&void 0!==i&&i.fileUrl?null===i||void 0===i?void 0:i.fileUrl:null,fromUserId:null===i||void 0===i?void 0:i.fromUserId,fromUserName:null!==i&&void 0!==i&&i.fromUserName?null===i||void 0===i?void 0:i.fromUserName:null!==y&&void 0!==y&&y.userName?null===y||void 0===y?void 0:y.userName:null,image:null!==i&&void 0!==i&&i.image?null===i||void 0===i?void 0:i.image:null,imageUrl:null!==i&&void 0!==i&&i.imageUrl?null===i||void 0===i?void 0:i.imageUrl:null,inboxId:null===i||void 0===i?void 0:i.inboxId,message:null===i||void 0===i?void 0:i.message,messageId:null!==i&&void 0!==i&&i.messageId?null===i||void 0===i?void 0:i.messageId:null,toUserId:null===i||void 0===i?void 0:i.toUserId,toUserName:null!==i&&void 0!==i&&i.toUserName?null===i||void 0===i?void 0:i.toUserName:null};e((0,x.FT)(n))}})))}),[j.W,y]);const Z=e=>{j.W.emit("sendMessage",{userIds:[{id:null===y||void 0===y?void 0:y.userId}],data:JSON.stringify(null===e||void 0===e?void 0:e.data),type:"inteli_health"})},D=s=>{const a={inboxId:null===y||void 0===y?void 0:y.inboxId,fromUserId:null===C||void 0===C?void 0:C.userId,toUserId:null===y||void 0===y?void 0:y.userId,message:h||"",isChat:!0};e((0,x.bG)({finalData:a,moveToNext:Z})),s.preventDefault(),b("")};(0,l.useEffect)((()=>{const s={inboxId:null===y||void 0===y?void 0:y.inboxId};e((0,x.SO)(s))}),[e,null===y||void 0===y?void 0:y.inboxId]),(0,l.useEffect)((()=>{e((0,x.VH)({search:""}))}),[e]),(0,l.useEffect)((()=>{var e;null===(e=s.current)||void 0===e||e.scrollIntoView({behavior:"smooth"})}),[W]);return(0,p.jsx)(p.Fragment,{children:(0,p.jsx)(i.Z,{className:"h-100 chatSection",children:(0,p.jsx)(i.Z.Body,{className:"py-0 px-0",children:(0,p.jsx)(n.Z,{fluid:!0,className:"",children:(0,p.jsxs)(d.Z,{className:"staff-chat",children:[(0,p.jsxs)(r.Z,{xl:4,lg:12,md:12,className:"borderRight pt-4 paddingBottom chat-box-shadow-lt",children:[(0,p.jsxs)("div",{children:[(0,p.jsx)("h3",{className:"fw-bold mb-3 px-4",children:"Messages"}),(0,p.jsxs)("span",{className:"d-flex align-self-center justify-content-center px-4",children:[(0,p.jsx)(t.Z.Control,{type:"text",placeholder:"Search",className:"w-100","aria-label":"Search"}),(0,p.jsx)(m.Goc,{size:22,className:"searchbar-icon"})]})]}),(0,p.jsxs)("div",{className:"mt-2",children:[(0,p.jsx)("div",{className:"px-4",children:(0,p.jsxs)(o.Z,{className:"user-dropdown chat_dropdown",children:[(0,p.jsx)(o.Z.Toggle,{id:"dropdown-basic",className:"px-0",children:(0,p.jsxs)("span",{className:"",children:["Sort By ",(0,p.jsx)(v.IAR,{className:""})]})}),(0,p.jsxs)(o.Z.Menu,{className:"",children:[(0,p.jsx)(o.Z.Item,{className:"",children:"Chat"}),(0,p.jsx)(o.Z.Item,{children:"Name"})]})]})}),(0,p.jsx)("div",{className:"staff-inbox",children:null===w||void 0===w?void 0:w.map((s=>(0,p.jsxs)("div",{className:"userChat mobileFlex_reverse d-flex justify-content-between align-items-center chatList_margin ".concat(y&&y.inboxId===s.inboxId?"activeChat":"hoverChat"),onClick:()=>(s=>{I(s),b("");const a={inboxId:null===y||void 0===y?void 0:y.inboxId};e((0,x.Fd)(a))})(s),children:[(0,p.jsxs)("div",{className:"d-flex mobileFlex_between align-items-center px-4",children:[(0,p.jsx)("span",{children:(0,p.jsx)("img",{className:"w-25 rounded-circle",src:s.imageUrl?s.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(s.userName),"&background=6045eb&color=fff"),alt:"UserImage"})}),(0,p.jsxs)("div",{className:"d-flex flex-column align-items-start ms-3 mt-2",children:[(0,p.jsx)("h5",{className:"mb-1 fw-semibold mobileTextHeading ",children:s.userName?s.userName:"N/A"}),(0,p.jsx)("p",{className:"color_light mobileText  message-container",children:s.message?s.message:""})]})]}),(0,p.jsxs)("div",{className:"d-flex flex-column justify-content-center align-items-end pr-4",style:{paddingRight:"12px"},children:[(0,p.jsx)("p",{className:"color_light fs-6 mb-1",children:s.createdDate?N()(s.createdDate).format("HH:MM A"):""}),(0,p.jsx)("span",{className:"chatCount text-white rounded",children:s.unreadCount?s.unreadCount:""})]})]},s.inboxId)))})]})]}),(0,p.jsx)(r.Z,{xl:8,lg:12,md:12,className:"px-0 chatContent chat-box-shadow-rt",children:y?(0,p.jsxs)(p.Fragment,{children:[(0,p.jsx)("div",{className:"d-flex justify-content-between mobileFlex_Col py-2 border-bottom px-4 ",children:(0,p.jsx)("div",{className:"d-flex justify-content-center align-items-center chatActive mb-sm-0 mb-3",children:(0,p.jsxs)("div",{className:"d-flex align-items-center py-0",children:[(0,p.jsx)("span",{children:(0,p.jsx)("img",{className:"rounded-circle",src:y.imageUrl?y.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(y.userName),"&background=6045eb&color=fff"),alt:"UserImage"})}),(0,p.jsx)("h5",{className:"fw-semibold mb-0 ms-3 mobileTextHeading",children:y.userName})]})})}),(0,p.jsxs)("div",{children:[(0,p.jsx)("div",{className:"div-fixed-height",style:{background:"#FBFBFB"},children:null!==W?null===W||void 0===W?void 0:W.map(((e,a)=>{var l,i,n,t,o;return(0,p.jsxs)(p.Fragment,{children:[(0,p.jsx)("div",{className:"d-flex flex-column h-100 px-4 py-3 chatBox",children:(0,p.jsxs)("div",{children:[(null===W||void 0===W||null===(l=W[a-1])||void 0===l||null===(i=l.createdDate)||void 0===i||null===(n=i.split("T"))||void 0===n?void 0:n[0])!==(null===e||void 0===e||null===(t=e.createdDate)||void 0===t||null===(o=t.split("T"))||void 0===o?void 0:o[0])&&(0,p.jsx)("div",{className:"text-center rounded-pill mx-auto chatSpan bg-white",children:N()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")===N()(new Date).format("DD-MM-YYYY")?"Today":N()(null===e||void 0===e?void 0:e.createdDate).format("DD-MM-YYYY")}),(0,p.jsx)("div",{children:(0,p.jsx)(d.Z,{children:(null===e||void 0===e?void 0:e.fromUserId)!==(null===C||void 0===C?void 0:C.userId)?(0,p.jsxs)(r.Z,{lg:8,md:6,className:"d-flex flex-column justify-content-start",children:[(0,p.jsxs)("div",{className:"chatMessage_left d-flex justify-content-start align-items-center mobileFlex_Col mb-1",children:[(0,p.jsx)("img",{className:"me-2 mb-2 mb-sm-0 rounded-circle",style:{width:"50px",height:"50px"},src:null!==e&&void 0!==e&&e.imageUrl?null===e||void 0===e?void 0:e.imageUrl:"https://ui-avatars.com/api/?name=".concat(null===e||void 0===e?void 0:e.fromUserName,"&background=6045eb&color=fff"),alt:"UserImage"}),(0,p.jsx)("span",{className:"messageSpan",children:null===e||void 0===e?void 0:e.message})]}),(0,p.jsx)("span",{className:"ms-5 chatTime",children:N()(null===e||void 0===e?void 0:e.createdDate).format("HH:MM A")})]}):(0,p.jsxs)(r.Z,{lg:4,md:6,className:"chatMessage_right text-white d-flex flex-column align-items-end justify-content-end w-100",children:[(0,p.jsx)("span",{className:"mb-1 mt-3 mobile_margin sender-message",children:null===e||void 0===e?void 0:e.message}),(0,p.jsx)("div",{className:"chatTime align-self-end",children:N()(null===e||void 0===e?void 0:e.createdDate).format("HH:MM A")})]})})})]})}),(0,p.jsx)("div",{ref:s})]})})):"No Message"}),(0,p.jsx)("div",{className:"border-top",children:(0,p.jsxs)("div",{className:"d-flex mobileFlex_Col justify-content-between align-items-center px-sm-4",children:[(0,p.jsx)("div",{className:"d-flex justify-content-center",children:(0,p.jsx)(c.Z,{className:"bg-transparent",type:"file",children:(0,p.jsx)("img",{className:"",src:u.Z.CLIP_ICON,alt:"clip",onClick:D})})}),(0,p.jsx)("div",{className:"w-100 d-flex miniFlex_Col",children:(0,p.jsxs)(t.Z.Group,{className:"position-relative py-3 w-100",children:[(0,p.jsx)(t.Z.Control,{className:"padding rounded-pill",placeholder:"Type a message here\u2026",value:h,onChange:e=>{b(e.target.value)},ref:a,onKeyDown:e=>{32===e.which&&0===a.current.selectionStart&&e.preventDefault()}}),(0,p.jsx)(c.Z,{className:"sendIcon rounded-circle",onClick:D,disabled:""===h,children:(0,p.jsx)("img",{src:u.Z.SEND_ICON,alt:"messageIcon"})})]})})]})})]})]}):(0,p.jsxs)("h5",{className:"mb-0 text-center text-black-50 d-flex justify-content-center align-items-center h-100",children:["Welcome to our chat system ",(0,p.jsx)("br",{})," Please feel free to start typing your message"]})})]})})})})})}},95070:(e,s,a)=>{a.d(s,{Z:()=>M});var l=a(81694),i=a.n(l),n=a(72791),d=a(10162),r=a(80184);const t=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n="div",...t}=e;return l=(0,d.vE)(l,"card-body"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));t.displayName="CardBody";const o=t,c=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n="div",...t}=e;return l=(0,d.vE)(l,"card-footer"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));c.displayName="CardFooter";const m=c;var v=a(96040);const u=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,as:t="div",...o}=e;const c=(0,d.vE)(a,"card-header"),m=(0,n.useMemo)((()=>({cardHeaderBsPrefix:c})),[c]);return(0,r.jsx)(v.Z.Provider,{value:m,children:(0,r.jsx)(t,{ref:s,...o,className:i()(l,c)})})}));u.displayName="CardHeader";const x=u,f=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,variant:n,as:t="img",...o}=e;const c=(0,d.vE)(a,"card-img");return(0,r.jsx)(t,{ref:s,className:i()(n?"".concat(c,"-").concat(n):c,l),...o})}));f.displayName="CardImg";const h=f,N=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n="div",...t}=e;return l=(0,d.vE)(l,"card-img-overlay"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));N.displayName="CardImgOverlay";const g=N,j=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n="a",...t}=e;return l=(0,d.vE)(l,"card-link"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));j.displayName="CardLink";const p=j;var b=a(27472);const y=(0,b.Z)("h6"),I=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n=y,...t}=e;return l=(0,d.vE)(l,"card-subtitle"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));I.displayName="CardSubtitle";const C=I,w=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n="p",...t}=e;return l=(0,d.vE)(l,"card-text"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));w.displayName="CardText";const W=w,U=(0,b.Z)("h5"),Z=n.forwardRef(((e,s)=>{let{className:a,bsPrefix:l,as:n=U,...t}=e;return l=(0,d.vE)(l,"card-title"),(0,r.jsx)(n,{ref:s,className:i()(a,l),...t})}));Z.displayName="CardTitle";const D=Z,E=n.forwardRef(((e,s)=>{let{bsPrefix:a,className:l,bg:n,text:t,border:c,body:m=!1,children:v,as:u="div",...x}=e;const f=(0,d.vE)(a,"card");return(0,r.jsx)(u,{ref:s,...x,className:i()(l,f,n&&"bg-".concat(n),t&&"text-".concat(t),c&&"border-".concat(c)),children:m?(0,r.jsx)(o,{children:v}):v})}));E.displayName="Card";const M=Object.assign(E,{Img:h,Title:D,Subtitle:C,Body:o,Link:p,Text:W,Header:x,Footer:m,ImgOverlay:g})},96040:(e,s,a)=>{a.d(s,{Z:()=>i});const l=a(72791).createContext(null);l.displayName="CardHeaderContext";const i=l},47022:(e,s,a)=>{a.d(s,{Z:()=>o});var l=a(81694),i=a.n(l),n=a(72791),d=a(10162),r=a(80184);const t=n.forwardRef(((e,s)=>{let{bsPrefix:a,fluid:l=!1,as:n="div",className:t,...o}=e;const c=(0,d.vE)(a,"container"),m="string"===typeof l?"-".concat(l):"-fluid";return(0,r.jsx)(n,{ref:s,...o,className:i()(t,l?"".concat(c).concat(m):c)})}));t.displayName="Container";const o=t},11701:(e,s,a)=>{a.d(s,{Ed:()=>n,UI:()=>i,XW:()=>d});var l=a(72791);function i(e,s){let a=0;return l.Children.map(e,(e=>l.isValidElement(e)?s(e,a++):e))}function n(e,s){let a=0;l.Children.forEach(e,(e=>{l.isValidElement(e)&&s(e,a++)}))}function d(e,s){return l.Children.toArray(e).some((e=>l.isValidElement(e)&&e.type===s))}},27472:(e,s,a)=>{a.d(s,{Z:()=>r});var l=a(72791),i=a(81694),n=a.n(i),d=a(80184);const r=e=>l.forwardRef(((s,a)=>(0,d.jsx)("div",{...s,ref:a,className:n()(s.className,e)})))}}]);
//# sourceMappingURL=3083.83a9b3a2.chunk.js.map