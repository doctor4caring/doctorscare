"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[6085],{52268:(e,l,s)=>{s.d(l,{Tf:()=>d,bA:()=>a,lt:()=>r,sP:()=>t});const a=[{lookupId:6,value:"Nurse"},{lookupId:7,value:"Receptionist"}],t=[{lookupId:101,value:"Male"},{lookupId:102,value:"Female"},{lookupId:103,value:"Other"}],d={Destroyed:"destroyed",Error:"error",Incoming:"incoming",Registered:"registered",Registering:"registering",TokenWillExpire:"tokenWillExpire",Unregistered:"unregistered"},r={Connected:"connected",Accept:"accept",Audio:"audio",Cancel:"cancel",Disconnect:"disconnect",Error:"error",Mute:"mute",Reconnected:"reconnected",Reconnecting:"reconnecting",Reject:"reject",Ringing:"ringing",Sample:"sample",Volume:"volume",WarningCleared:"warning-cleared",Warning:"warning"}},38713:(e,l,s)=>{s.d(l,{c:()=>n});s(72791);var a=s(88135),t=s(43360),d=s(39126),r=s(80184);function n(e){return(0,r.jsx)(r.Fragment,{children:(0,r.jsxs)(a.Z,{show:e.show,onHide:e.onHide,size:"lg","aria-labelledby":"contained-modal-title-vcenter",centered:!0,className:"appointment-modal",children:[(0,r.jsx)(a.Z.Header,{closeButton:!0}),(0,r.jsxs)(a.Z.Body,{children:[(0,r.jsx)("div",{className:"d-flex justify-content-center",children:(0,r.jsx)("div",{className:"p-4 rounded-circle m-auto",style:{background:"#EDEAFD"},children:(0,r.jsx)(d.yvY,{className:"fw-bold",size:"24",style:{color:"#6045EB"}})})}),(0,r.jsx)("h3",{className:"text-center mx-auto mt-4",style:{fontWeight:600},children:e.heading}),(0,r.jsxs)("p",{className:"text-center mt-3 mb-4",children:["Are you sure you want to delete ",e.title,"?"]}),(0,r.jsx)("span",{className:"d-flex justify-content-center",children:(0,r.jsx)(t.Z,{style:{background:"#FD2121",border:"none"},className:"px-4 mb-3",onClick:()=>{e.removeFunc(),e.onHide()},children:"Delete"})})]})]})})}},76085:(e,l,s)=>{s.r(l),s.d(l,{default:()=>T});var a=s(72791),t=s(61734),d=s(89743),r=s(2677),n=s(36957),o=(s(68639),s(56355)),i=s(95070),c=s(36638),u=s(7692),m=s(2002),h=s(36161),x=s(17425),j=s(59513),p=s.n(j),v=s(39126),b=s(59434),f=s(80591),g=s(46587),N=s(88135),Z=s(43360),I=s(52268),w=s(75737),y=s.n(w),F=(s(98404),s(61134)),A=s(80184);function S(e){let{show:l,onClose:s,data:t}=e;const{register:n,handleSubmit:o,setValue:i,reset:u,control:m}=(0,F.cI)(),{user:h}=(0,b.v9)((e=>e.auth)),x=(0,b.I0)();function j(){let e={userId:h.userId,roleId:5};x((0,f.lE)({finalData:e}))}return(0,a.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,A.jsx)(A.Fragment,{children:(0,A.jsx)(N.Z,{show:l,onHide:s,size:"md",children:(0,A.jsxs)(c.Z,{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:5,email:e.email,password:e.password,phoneNumber:e.phoneNumber,firstName:e.firstName,lastName:e.lastName,staffRoleId:e.staffRoleId,genderId:null===e||void 0===e?void 0:e.genderId};x(t?(0,f.Nq)({finalData:l,onCreateSuccess:j}):(0,f.r4)({finalData:l,onCreateSuccess:j})),s(),u()})),children:[(0,A.jsx)(N.Z.Header,{closeButton:!0,children:(0,A.jsxs)(N.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Staff"]})}),(0,A.jsx)(N.Z.Body,{className:"p-4",children:(0,A.jsxs)(d.Z,{children:[(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formFirstName",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"First Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formLastName",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Email"}),(0,A.jsx)(c.Z.Control,{type:"email",placeholder:"Enter email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formPassword",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Password "}),(0,A.jsx)(c.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),disabled:t,maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,A.jsx)(F.Qr,{control:m,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,A.jsx)(y(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,A.jsxs)(r.Z,{lg:12,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Role"}),(0,A.jsxs)(c.Z.Select,{"aria-label":"Select Role",...n("staffRoleId",{required:!t}),defaultValue:null===t||void 0===t?void 0:t.staffRoleId,children:[(0,A.jsx)("option",{children:"Select Status"}),I.bA.map((e=>(0,A.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.value})))]})]}),(0,A.jsxs)(r.Z,{lg:12,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Gender "}),(0,A.jsxs)(c.Z.Select,{...n("genderId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select Gender"}),I.sP.map((e=>(0,A.jsx)("option",{value:+(null===e||void 0===e?void 0:e.lookupId),children:e.value})))]})]})]})}),(0,A.jsxs)(N.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,A.jsx)(Z.Z,{onClick:s,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,A.jsxs)(Z.Z,{variant:"primary",className:"Admin-Add-btn fw-bold",type:"submit",children:[t?"Update":"Add"," Staff"]})]})]})})})}var C=s(38713),k=s(72426),D=s.n(k);function L(e){var l,s,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,j]=(0,a.useState)(!1),[N,Z]=(0,a.useState)(null),[I,w]=(0,a.useState)(),[y,F]=(0,a.useState)(),k=(0,b.v9)((e=>e)),{isLoading:L}=(0,b.v9)((e=>e.userRole)),E=(0,b.I0)();function P(){let e={userId:k.auth.user.userId,roleId:5};E((0,f.lE)({finalData:e}))}(0,a.useEffect)((()=>{const e={roleId:5,search:y||null,dob:N?D()(N).format("YYYY-MM-DD"):null};E((0,f.lE)({finalData:e}))}),[E,y,N]);const B=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Staff Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"}},{dataField:"email",text:"Email",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"phoneNumber",text:"Phone Number",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const l=new Date(e),s=l.getDate().toString().padStart(2,"0"),a=(l.getMonth()+1).toString().padStart(2,"0"),t=l.getFullYear();return"".concat(a,"/").concat(s,"/").concat(t)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,A.jsxs)(A.Fragment,{children:[(0,A.jsx)(u.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},onClick:()=>r({data:l,show:!0})}),(0,A.jsx)(x.AWu,{style:{color:"red",cursor:"pointer"},className:"ms-3",onClick:()=>{w(null===l||void 0===l?void 0:l.userId),j(!0)}})]}),headerStyle:{backgroundColor:"#F1F1F1"}}],z={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,s)=>(0,A.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,A.jsxs)("b",{children:[" ",e," "]})," to ",(0,A.jsx)("b",{children:l})," out of ",(0,A.jsxs)("b",{children:[s," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)(i.Z,{className:"user-details-card",children:[(0,A.jsxs)("div",{className:"px-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,A.jsxs)("span",{className:"d-flex align-self-center",children:[(0,A.jsx)(c.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&F(e.target.value)},onChange:e=>{"Enter"===e.key&&F(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing",style:{width:"100%"},"aria-label":"Search"}),(0,A.jsx)(u.Goc,{size:22,className:"searchbar-icon"})]}),(0,A.jsxs)("div",{className:"d-flex custom-div-row",children:[(0,A.jsx)(p(),{selected:N,onChange:e=>Z(e),dateFormat:"dd MMM yyyy",placeholderText:"Date",className:"custom-field-picker dr-date-w px-3 mb-3"}),(0,A.jsx)(v.zlR,{className:"custom-date-icon",size:18,style:{right:"32px"}})]})]}),L?(0,A.jsx)(g.Z,{}):(0,A.jsx)("span",{className:"doctor-datatable",children:(0,A.jsx)(m.Z,{columns:B,data:null!==k&&void 0!==k&&null!==(l=k.userRole)&&void 0!==l&&null!==(s=l.getAllUser)&&void 0!==s&&s.data?null===k||void 0===k||null===(t=k.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,h.ZP)(z),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,A.jsx)(C.c,{show:o,onHide:()=>j(!1),heading:"Delete Staff",title:"this staff",removeFunc:function(){const e={userId:I};E((0,f.h8)({finalData:e,onDeleteSuccess:P}))}}),(0,A.jsx)(S,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function E(e){let{show:l,onClose:s,data:t}=e;const{register:n,handleSubmit:o,setValue:i,reset:u,control:m}=(0,F.cI)(),{user:h}=(0,b.v9)((e=>e.auth)),x=(0,b.I0)();function j(){let e={userId:h.userId,roleId:3};x((0,f.lE)({finalData:e}))}return(0,a.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("currentAddress",(null===t||void 0===t?void 0:t.currentAddress)||""),i("dob",(null===t||void 0===t?void 0:t.dob)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,A.jsx)(A.Fragment,{children:(0,A.jsx)(N.Z,{show:l,onHide:s,size:"lg",children:(0,A.jsxs)(c.Z,{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:3,email:e.email,phoneNumber:e.phoneNumber,firstName:e.firstName,lastName:e.lastName,currentAddress:e.currentAddress,genderId:null===e||void 0===e?void 0:e.genderId,dob:e.dob,password:e.password,staffRoleId:5,image:null};x(t?(0,f.Nq)({finalData:l,onCreateSuccess:j}):(0,f.r4)({finalData:l,onCreateSuccess:j})),s(),u()})),children:[(0,A.jsx)(N.Z.Header,{closeButton:!0,children:(0,A.jsxs)(N.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Patient"]})}),(0,A.jsx)(N.Z.Body,{className:"p-4",children:(0,A.jsxs)(d.Z,{children:[(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"First Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Password"}),(0,A.jsx)(c.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),disabled:t,maxLength:50})]})}),(0,A.jsxs)(r.Z,{lg:6,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Gender "}),(0,A.jsxs)(c.Z.Select,{...n("genderId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select Gender"}),I.sP.map((e=>(0,A.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.value})))]})]}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"D.O.B"}),(0,A.jsx)(c.Z.Control,{type:"date",size:"lg",...n("dob",{required:!0}),defaultValue:D()(null===t||void 0===t?void 0:t.dob).format("YYYY-MM-DD"),max:D()(new Date).format("YYYY-MM-DD")})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Email "}),(0,A.jsx)(c.Z.Control,{type:"email",placeholder:"Email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,A.jsx)(F.Qr,{control:m,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,A.jsx)(y(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Current Address"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Type Address here",size:"lg",...n("currentAddress",{required:!t})})]})})]})}),(0,A.jsxs)(N.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,A.jsx)(Z.Z,{onClick:s,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,A.jsxs)(Z.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:[t?"Update":"Add"," Patient"]})]})]})})})}function P(e){var l,s,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,j]=(0,a.useState)(!1),[N,Z]=(0,a.useState)(),[I,w]=(0,a.useState)(),[y,F]=(0,a.useState)(null),[S,k]=(0,a.useState)(),L=(0,b.v9)((e=>e)),{isLoading:P}=(0,b.v9)((e=>e.userRole)),B=(0,b.I0)();function z(){let e={userId:L.auth.user.userId,roleId:3};B((0,f.lE)({finalData:e}))}(0,a.useEffect)((()=>{const e={roleId:3,search:I,genderId:"101"===S?101:"102"===S?102:null,dob:y?D()(y).format("YYYY-MM-DD"):null};B((0,f.lE)({finalData:e}))}),[B,I,S,y]);const G=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"},formatter:(e,l)=>(0,A.jsxs)("div",{className:"d-flex align-items-center",children:[(0,A.jsx)("img",{src:null!==l&&void 0!==l&&l.imageUrl?null===l||void 0===l?void 0:l.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"patient",className:"me-2 dt-round-img"}),(0,A.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,A.jsx)("p",{className:"m-0 table-bold-text",children:null===l||void 0===l?void 0:l.name}),(0,A.jsx)("p",{className:"m-0 table-normal-text",children:null===l||void 0===l?void 0:l.email}),(0,A.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===l||void 0===l?void 0:l.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"genderName",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"dob",text:"DOB",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const l=new Date(e),s=l.getDate().toString().padStart(2,"0"),a=(l.getMonth()+1).toString().padStart(2,"0"),t=l.getFullYear();return"".concat(a,"/").concat(s,"/").concat(t)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,A.jsxs)(A.Fragment,{children:[(0,A.jsx)(u.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},onClick:()=>r({data:l,show:!0})}),(0,A.jsx)(x.AWu,{style:{color:"red",cursor:"pointer"},className:"ms-3",onClick:()=>{Z(null===l||void 0===l?void 0:l.userId),j(!0)}})]}),headerStyle:{backgroundColor:"#F1F1F1"}}],R={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,s)=>(0,A.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,A.jsxs)("b",{children:[" ",e," "]})," to ",(0,A.jsx)("b",{children:l})," out of ",(0,A.jsxs)("b",{children:[s," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)(i.Z,{className:"user-details-card",children:[(0,A.jsxs)("div",{className:"ps-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,A.jsx)("div",{children:(0,A.jsxs)("span",{className:"d-flex align-self-center",children:[(0,A.jsx)(c.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&w(e.target.value)},onChange:e=>{"Enter"===e.key&&w(e.target.value)},type:"text",placeholder:"Search",className:"mb-3 search-field-spacing","aria-label":"Search"}),(0,A.jsx)(u.Goc,{size:22,className:"searchbar-icon"})]})}),(0,A.jsxs)("div",{className:"mainDiv",children:[(0,A.jsx)("div",{className:"mb-",children:(0,A.jsxs)("select",{onChange:e=>k(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,A.jsx)("option",{selected:!0,children:"Gender"}),(0,A.jsx)("option",{value:101,children:"Male"}),(0,A.jsx)("option",{value:102,children:"Female"})]})}),(0,A.jsx)(p(),{selected:y,onChange:e=>F(e),dateFormat:"dd MMM yyyy",placeholderText:"DOB",className:"custom-field-picker dr-date-w px-3"}),(0,A.jsx)(v.zlR,{className:"custom-date-icon",size:18,style:{right:"42px"}})]})]}),P?(0,A.jsx)(g.Z,{}):(0,A.jsx)("span",{className:"doctor-datatable",children:(0,A.jsx)(m.Z,{columns:G,data:null!==L&&void 0!==L&&null!==(l=L.userRole)&&void 0!==l&&null!==(s=l.getAllUser)&&void 0!==s&&s.data?null===L||void 0===L||null===(t=L.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,h.ZP)(R),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,A.jsx)(C.c,{show:o,onHide:()=>j(!1),heading:"Delete Patient",title:"this patient",removeFunc:function(){const e={userId:N};B((0,f.h8)({finalData:e,onDeleteSuccess:z}))}}),(0,A.jsx)(E,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function B(e){let{show:l,onClose:s,data:t}=e;const{register:n,handleSubmit:o,setValue:i,reset:u,control:m}=(0,F.cI)(),{user:h}=(0,b.v9)((e=>e.auth)),x=(0,b.I0)();function j(){let e={userId:h.userId,roleId:2};x((0,f.lE)({finalData:e}))}return(0,a.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("mcrn",(null===t||void 0===t?void 0:t.mcrn)||""),i("currentAddress",(null===t||void 0===t?void 0:t.currentAddress)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("statusId",t?1==(null===t||void 0===t?void 0:t.statusId)?1:2:""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,A.jsx)(A.Fragment,{children:(0,A.jsx)(N.Z,{show:l,onHide:s,size:"lg",children:(0,A.jsxs)(c.Z,{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:2,email:e.email,password:e.password,phoneNumber:e.phoneNumber,statusId:1==e.statusId,firstName:e.firstName,lastName:e.lastName,currentAddress:e.currentAddress,mcrn:null===e||void 0===e?void 0:e.mcrn,genderId:null===e||void 0===e?void 0:e.genderId};x(t?(0,f.Nq)({finalData:l,onCreateSuccess:j}):(0,f.r4)({finalData:l,onCreateSuccess:j})),s(),u()})),children:[(0,A.jsx)(N.Z.Header,{closeButton:!0,children:(0,A.jsxs)(N.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Doctor"]})}),(0,A.jsx)(N.Z.Body,{className:"p-4",children:(0,A.jsxs)(d.Z,{children:[(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"First Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Email "}),(0,A.jsx)(c.Z.Control,{type:"email",placeholder:"Email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Password "}),(0,A.jsx)(c.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),disabled:t,maxLength:50})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,A.jsx)(F.Qr,{control:m,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,A.jsx)(y(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"MCRN "}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"MCRN Number",size:"lg",...n("mcrn",{required:!t}),maxLength:50})]})}),(0,A.jsxs)(r.Z,{lg:6,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Status"}),(0,A.jsxs)(c.Z.Select,{"aria-label":"Select Status",...n("statusId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select status"}),(0,A.jsx)("option",{value:"1",children:"Active"}),(0,A.jsx)("option",{value:"2",children:"Inactive"})]})]}),(0,A.jsxs)(r.Z,{lg:6,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Gender "}),(0,A.jsxs)(c.Z.Select,{...n("genderId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select Gender"}),I.sP.map((e=>(0,A.jsx)("option",{value:+(null===e||void 0===e?void 0:e.lookupId),children:e.value})))]})]}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{controlId:"formBasicEmail",className:"mt-3",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Address"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Type Address here",size:"lg",...n("currentAddress",{required:!t}),maxLength:150})]})})]})}),(0,A.jsxs)(N.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,A.jsx)(Z.Z,{onClick:s,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,A.jsxs)(Z.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:[t?"Update":"Add"," Doctor"]})]})]})})})}function z(e){var l,s,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,j]=(0,a.useState)(),p=(0,b.v9)((e=>e)),{isLoading:v}=(0,b.v9)((e=>e.userRole)),[N,Z]=(0,a.useState)(),[I,w]=(0,a.useState)(null),[y,F]=(0,a.useState)(),[S,k]=(0,a.useState)(!1),D=(0,b.I0)();function L(){let e={userId:p.auth.user.userId,roleId:2};D((0,f.lE)({finalData:e}))}(0,a.useEffect)((()=>{const e={roleId:2,search:o||null,statusId:"true"===I||"false"!==I&&null,genderId:"101"===y?101:"102"===y?102:null};D((0,f.lE)({finalData:e}))}),[D,o,I,y]);const E=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Doctor Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"},formatter:(e,l)=>(0,A.jsxs)("div",{className:"d-flex align-items-center",children:[(0,A.jsx)("img",{src:null!==l&&void 0!==l&&l.imageUrl?null===l||void 0===l?void 0:l.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"doctor",className:"me-2 dt-round-img"}),(0,A.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,A.jsx)("p",{className:"m-0 table-bold-text",children:null===l||void 0===l?void 0:l.name}),(0,A.jsx)("p",{className:"m-0 table-normal-text",children:null===l||void 0===l?void 0:l.email}),(0,A.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===l||void 0===l?void 0:l.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"mcrn",text:"MCRN",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"genderName",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"status",text:"Status",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,l)=>(0,A.jsx)("p",{className:"mb-0 text-center py-1 custom-width-class ".concat("InActive"===(null===l||void 0===l?void 0:l.status)?"inactive-status":"active-status"),children:"InActive"===(null===l||void 0===l?void 0:l.status)?"Inactive":"Active"})},{dataField:"action",text:"Actions",sort:!1,formatter:(e,l)=>(0,A.jsxs)(A.Fragment,{children:[(0,A.jsx)(u.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},onClick:()=>r({data:l,show:!0})}),(0,A.jsx)(x.AWu,{style:{color:"red",cursor:"pointer"},className:"ms-3",onClick:()=>{Z(null===l||void 0===l?void 0:l.userId),k(!0)}})]}),headerStyle:{backgroundColor:"#F1F1F1"}}],P={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,s)=>(0,A.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,A.jsxs)("b",{children:[" ",e," "]})," to ",(0,A.jsx)("b",{children:l})," out of ",(0,A.jsxs)("b",{children:[s," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)(i.Z,{className:"user-details-card",children:[(0,A.jsxs)("div",{className:"px-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,A.jsxs)("span",{className:"d-flex align-self-center",children:[(0,A.jsx)(c.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&j(e.target.value)},onChange:e=>{"Enter"===e.key&&j(e.target.value)},type:"text",placeholder:"Search",className:"mb-3 search-field-spacing","aria-label":"Search"}),(0,A.jsx)(u.Goc,{size:22,className:"searchbar-icon"})]}),(0,A.jsxs)("div",{className:"d-flex",children:[(0,A.jsx)("div",{className:"mb-2 me-2",children:(0,A.jsxs)("select",{onChange:e=>F(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,A.jsx)("option",{selected:!0,children:"Gender"}),(0,A.jsx)("option",{value:101,children:"Male"}),(0,A.jsx)("option",{value:102,children:"Female"})]})}),(0,A.jsx)("div",{className:"mb-2",children:(0,A.jsxs)("select",{onClick:e=>w(e.target.value),class:"form-select pe-5","aria-label":"Default select example",children:[(0,A.jsx)("option",{selected:!0,children:"Status"}),(0,A.jsx)("option",{value:"true",children:"Active"}),(0,A.jsx)("option",{value:"false",children:"Inactive"})]})})]})]}),v?(0,A.jsx)(g.Z,{}):(0,A.jsx)("span",{className:"doctor-datatable",children:(0,A.jsx)(m.Z,{columns:E,data:null!==p&&void 0!==p&&null!==(l=p.userRole)&&void 0!==l&&null!==(s=l.getAllUser)&&void 0!==s&&s.data?null===p||void 0===p||null===(t=p.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,h.ZP)(P),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,A.jsx)(C.c,{show:S,onHide:()=>k(!1),heading:"Delete Doctor",title:"this doctor",removeFunc:function(){const e={userId:N};D((0,f.h8)({finalData:e,onDeleteSuccess:L}))}}),(0,A.jsx)(B,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function G(e){let{show:l,onClose:s,data:t}=e;const{register:n,handleSubmit:o,setValue:i,control:u,reset:m}=(0,F.cI)(),{user:h}=(0,b.v9)((e=>e.auth)),x=(0,b.I0)();function j(){let e={userId:h.userId,roleId:4};x((0,f.lE)({finalData:e})),s(),m()}return(0,a.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("statusId",t?1==(null===t||void 0===t?void 0:t.statusId)?1:2:""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,A.jsx)(A.Fragment,{children:(0,A.jsx)(N.Z,{show:l,onHide:s,size:"md",children:(0,A.jsxs)("form",{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:4,email:e.email,password:e.password,phoneNumber:e.phoneNumber,statusId:1==e.statusId,firstName:e.firstName,lastName:e.lastName,genderId:null===e||void 0===e?void 0:e.genderId};x(t?(0,f.Nq)({finalData:l,onCreateSuccess:j}):(0,f.r4)({finalData:l,onCreateSuccess:j}))})),children:[(0,A.jsx)(N.Z.Header,{closeButton:!0,children:(0,A.jsxs)(N.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Admin"]})}),(0,A.jsx)(N.Z.Body,{className:"p-4",children:(0,A.jsxs)(d.Z,{children:[(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"First Name"}),(0,A.jsx)(c.Z.Control,{size:"lg",type:"text",placeholder:"John",maxLength:50,...n("firstName",{required:!t})})]})}),(0,A.jsx)(r.Z,{lg:6,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,A.jsx)(c.Z.Control,{type:"text",placeholder:"Smith",size:"lg",maxLength:50,...n("lastName",{required:!t})})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Email"}),(0,A.jsx)(c.Z.Control,{type:"email",placeholder:"Enter email",size:"lg",maxLength:50,...n("email",{required:!t})})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Password "}),(0,A.jsx)(c.Z.Control,{type:"password",placeholder:"Password",size:"lg",maxLength:50,...n("password",{required:!t}),disabled:t})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,A.jsx)(F.Qr,{control:u,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,A.jsx)(y(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,A.jsx)(r.Z,{lg:12,children:(0,A.jsxs)(c.Z.Group,{className:"mb-3",controlId:"formStatus",children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Status"}),(0,A.jsxs)(c.Z.Select,{"aria-label":"Select Status",...n("statusId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select status"}),(0,A.jsx)("option",{value:"1",children:"Active"}),(0,A.jsx)("option",{value:"2",children:"Inactive"})]})]})}),(0,A.jsxs)(r.Z,{lg:12,children:[(0,A.jsx)(c.Z.Label,{className:"fw-bold",children:"Gender "}),(0,A.jsxs)(c.Z.Select,{...n("genderId",{required:!t}),children:[(0,A.jsx)("option",{value:"",children:"Select Gender"}),I.sP.map((e=>(0,A.jsx)("option",{value:+(null===e||void 0===e?void 0:e.lookupId),children:e.value})))]})]})]})}),(0,A.jsxs)(N.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,A.jsx)(Z.Z,{onClick:s,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,A.jsxs)(Z.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:[t?"Update":"Add"," Admin"]})]})]})})})}function R(e){var l,s,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,j]=(0,a.useState)(!1),[p,v]=(0,a.useState)(),[N,Z]=(0,a.useState)(null),[I,w]=(0,a.useState)(),y=(0,b.v9)((e=>e)),{isLoading:F}=(0,b.v9)((e=>e.userRole)),S=(0,b.I0)();function k(){let e={userId:y.auth.user.userId,roleId:4};S((0,f.lE)({finalData:e}))}(0,a.useEffect)((()=>{const e={roleId:4,search:I||null,statusId:"true"===N||"false"!==N&&null};S((0,f.lE)({finalData:e}))}),[S,I,N]);const D=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Admin Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"}},{dataField:"email",text:"Email",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"phoneNumber",text:"Phone Number",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"status",text:"Status",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,l)=>(0,A.jsx)("p",{className:"mb-0 text-center py-1 custom-width-class ".concat("InActive"===(null===l||void 0===l?void 0:l.status)?"inactive-status":"active-status"),children:"InActive"===(null===l||void 0===l?void 0:l.status)?"Inactive":"Active"})},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,A.jsxs)(A.Fragment,{children:[(0,A.jsx)(u.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},onClick:()=>r({data:l,show:!0})}),(0,A.jsx)(x.AWu,{style:{color:"red",cursor:"pointer"},className:"ms-3",onClick:()=>{v(null===l||void 0===l?void 0:l.userId),j(!0)}})]}),headerStyle:{backgroundColor:"#F1F1F1"}}],L={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,s)=>(0,A.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,A.jsxs)("b",{children:[" ",e," "]})," to ",(0,A.jsx)("b",{children:l})," out of ",(0,A.jsxs)("b",{children:[s," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,A.jsxs)(A.Fragment,{children:[(0,A.jsxs)(i.Z,{className:"user-details-card",children:[(0,A.jsxs)("div",{className:"px-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,A.jsxs)("span",{className:"d-flex align-self-center",children:[(0,A.jsx)(c.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&w(e.target.value)},onChange:e=>{"Enter"===e.key&&w(e.target.value)},type:"text",placeholder:"Search",className:"mb-3 search-field-spacing","aria-label":"Search"}),(0,A.jsx)(u.Goc,{size:22,className:"searchbar-icon"})]}),(0,A.jsx)("div",{className:"d-flex custom-div-row",children:(0,A.jsx)("div",{className:"mb-2",children:(0,A.jsxs)("select",{onClick:e=>Z(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,A.jsx)("option",{selected:!0,children:"Status"}),(0,A.jsx)("option",{value:"true",children:"Active"}),(0,A.jsx)("option",{value:"false",children:"Inactive"})]})})})]}),F?(0,A.jsx)(g.Z,{}):(0,A.jsx)("span",{className:"doctor-datatable",children:(0,A.jsx)(m.Z,{columns:D,data:null!==y&&void 0!==y&&null!==(l=y.userRole)&&void 0!==l&&null!==(s=l.getAllUser)&&void 0!==s&&s.data?null===y||void 0===y||null===(t=y.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,h.ZP)(L),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,A.jsx)(C.c,{show:o,onHide:()=>j(!1),heading:"Delete Admin",title:"this admin",removeFunc:function(){const e={userId:p};S((0,f.h8)({finalData:e,onDeleteSuccess:k}))}}),(0,A.jsx)(G,{data:n.data,show:n.show,setAddAdmin:r,onClose:()=>r({show:!1,data:null})})]})}var q=s(58617),M=s(70828);function T(){const[e,l]=(0,a.useState)({data:null,show:!1}),[s,i]=(0,a.useState)("admin"),{user:c}=(0,b.v9)((e=>e.auth));return(0,A.jsx)("div",{className:"usermanagement-mainclass",children:(0,A.jsx)(t.Z.Container,{id:"left-tabs-example",defaultActiveKey:"admin",className:"Admin-Tabs-SubMain",onSelect:e=>i(e),children:(0,A.jsxs)(d.Z,{children:[(0,A.jsx)(r.Z,{lg:9,md:9,sm:8,children:(0,A.jsxs)(n.Z,{variant:"pills",className:"flex-row Nav-MainAdmin",children:[1===(null===c||void 0===c?void 0:c.roleId)&&(0,A.jsx)(n.Z.Item,{className:"p-2 ps-0 ",children:(0,A.jsxs)(n.Z.Link,{eventKey:"admin",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,A.jsx)(o.Xws,{className:"me-2"})," Admin"]})}),(0,A.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,A.jsxs)(n.Z.Link,{eventKey:"doctor",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,A.jsx)(o.Z5v,{className:"me-2"}),"Doctor"]})}),(0,A.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,A.jsxs)(n.Z.Link,{eventKey:"patient",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,A.jsx)(M.eBc,{className:"me-2"}),"Patient"]})}),(0,A.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,A.jsxs)(n.Z.Link,{eventKey:"staff",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,A.jsx)(q.VcF,{className:"me-2",size:20}),"Staff"]})})]})}),(0,A.jsx)(r.Z,{lg:3,md:3,sm:4,children:(0,A.jsxs)(t.Z.Content,{className:"pt-0",children:[(0,A.jsx)(t.Z.Pane,{eventKey:"admin",children:(0,A.jsx)("div",{className:"d-flex justify-content-end ",children:(0,A.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Admin"})})}),(0,A.jsx)(t.Z.Pane,{eventKey:"doctor",children:(0,A.jsx)("div",{className:"d-flex justify-content-end ",children:(0,A.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Doctor"})})}),(0,A.jsx)(t.Z.Pane,{eventKey:"patient",children:(0,A.jsx)("div",{className:"d-flex justify-content-end ",children:(0,A.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Patient"})})}),(0,A.jsx)(t.Z.Pane,{eventKey:"staff",children:(0,A.jsx)("div",{className:"d-flex justify-content-end ",children:(0,A.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Staff"})})})]})}),(0,A.jsx)(r.Z,{lg:12,md:12,children:(0,A.jsxs)(t.Z.Content,{children:[(0,A.jsx)(t.Z.Pane,{eventKey:"admin",children:"admin"===s&&(0,A.jsx)(R,{addAdmin:e,setAddAdmin:l})}),(0,A.jsx)(t.Z.Pane,{eventKey:"doctor",children:"doctor"===s&&(0,A.jsx)(z,{addAdmin:e,setAddAdmin:l})}),(0,A.jsx)(t.Z.Pane,{eventKey:"patient",children:"patient"===s&&(0,A.jsx)(P,{addAdmin:e,setAddAdmin:l})}),(0,A.jsx)(t.Z.Pane,{eventKey:"staff",children:"staff"===s&&(0,A.jsx)(L,{addAdmin:e,setAddAdmin:l})})]})})]})})})}}}]);
//# sourceMappingURL=6085.4bd407a9.chunk.js.map