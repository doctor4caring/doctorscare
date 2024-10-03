"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[8215],{52268:(e,l,a)=>{a.d(l,{Tf:()=>d,_Y:()=>n,bA:()=>s,lt:()=>r,sP:()=>t});const s=[{lookupId:6,value:"Nurse"},{lookupId:7,value:"Receptionist"}],t=[{lookupId:101,value:"Male"},{lookupId:102,value:"Female"},{lookupId:103,value:"Other"}],d={Destroyed:"destroyed",Error:"error",Incoming:"incoming",Registered:"registered",Registering:"registering",TokenWillExpire:"tokenWillExpire",Unregistered:"unregistered"},r={Connected:"connected",Accept:"accept",Audio:"audio",Cancel:"cancel",Disconnect:"disconnect",Error:"error",Mute:"mute",Reconnected:"reconnected",Reconnecting:"reconnecting",Reject:"reject",Ringing:"ringing",Sample:"sample",Volume:"volume",WarningCleared:"warning-cleared",Warning:"warning"},n=[{lookupId:401,name:"Multiple Choice",value:"Radio"},{lookupId:402,name:"Checkbox",value:"Checkbox"},{lookupId:404,name:"Paragraph",value:"TextBox"}]},58215:(e,l,a)=>{a.r(l),a.d(l,{default:()=>B});var s=a(72791),t=a(61734),d=a(89743),r=a(2677),n=a(36957),o=a(56355),i=(a(68639),a(58617)),c=a(70828),m=a(95070),u=a(36638),h=a(7692),x=a(2002),j=a(36161),p=a(59434),v=a(80591),b=a(46587),g=a(88135),f=a(43360),N=a(75737),Z=a.n(N),w=(a(98404),a(52268)),y=a(61134),I=a(80184);function F(e){let{show:l,onClose:a,data:t}=e;const{register:n,handleSubmit:o,setValue:i,control:c,reset:m}=(0,y.cI)(),{user:h}=(0,p.v9)((e=>e.auth)),x=(0,p.I0)();function j(){let e={userId:h.userId,roleId:2};x((0,v.lE)({finalData:e}))}return(0,s.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("mcrn",(null===t||void 0===t?void 0:t.mcrn)||""),i("currentAddress",(null===t||void 0===t?void 0:t.currentAddress)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,I.jsx)(I.Fragment,{children:(0,I.jsx)(g.Z,{show:l,onHide:a,size:"lg",children:(0,I.jsxs)(u.Z,{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:2,email:e.email,password:e.password,phoneNumber:e.phoneNumber,statusId:1==e.statusId,firstName:e.firstName,lastName:e.lastName,currentAddress:e.currentAddress,mcrn:e.mcrn,genderId:null===e||void 0===e?void 0:e.genderId};x(t?(0,v.Nq)({finalData:l,onCreateSuccess:j}):(0,v.r4)({finalData:l,onCreateSuccess:j})),a(),m()})),children:[(0,I.jsx)(g.Z.Header,{closeButton:!0,children:(0,I.jsxs)(g.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Doctor"]})}),(0,I.jsx)(g.Z.Body,{className:"p-4",children:(0,I.jsxs)(d.Z,{children:[(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{controlId:"formFirstName",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"First Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{controlId:"formlastName",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,I.jsxs)(d.Z,{className:"mt-3",children:[(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Email "}),(0,I.jsx)(u.Z.Control,{type:"email",placeholder:"Email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formPassword",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Password "}),(0,I.jsx)(u.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),disabled:t,maxLength:50})]})})]}),(0,I.jsxs)(d.Z,{children:[(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,I.jsx)(y.Qr,{control:c,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,I.jsx)(Z(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formMCRN",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"MCRN "}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"MCRN Number",size:"lg",...n("mcrn",{required:!t}),maxLength:50})]})})]}),(0,I.jsxs)(d.Z,{children:[(0,I.jsxs)(r.Z,{lg:6,children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Status "}),(0,I.jsxs)(u.Z.Select,{"aria-label":"Select Status",...n("statusId",{required:!t}),children:[(0,I.jsx)("option",{value:"",children:"Select status"}),(0,I.jsx)("option",{value:"1",children:"Active"}),(0,I.jsx)("option",{value:"2",children:"Inactive"})]})]}),(0,I.jsxs)(r.Z,{lg:6,children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Gender "}),(0,I.jsxs)(u.Z.Select,{...n("genderId",{required:!t}),children:[(0,I.jsx)("option",{value:"",children:"Select Gender"}),w.sP.map((e=>(0,I.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.value})))]})]})]}),(0,I.jsx)(r.Z,{lg:12,children:(0,I.jsxs)(u.Z.Group,{className:"mt-3",controlId:"formAddress",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Address "}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"Type Address here",size:"lg",...n("currentAddress",{required:!t}),maxLength:150})]})})]})}),(0,I.jsxs)(g.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,I.jsx)(f.Z,{onClick:a,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,I.jsxs)(f.Z,{variant:"primary",className:"Admin-Add-btn fw-bold",type:"submit",children:[t?"Update":"Add"," Doctor"]})]})]})})})}function A(e){var l,a,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,i]=(0,s.useState)(),[c,g]=(0,s.useState)(),[f,N]=(0,s.useState)(null),Z=(0,p.v9)((e=>e)),{isLoading:w}=(0,p.v9)((e=>e.userRole)),y=(0,p.I0)();(0,s.useEffect)((()=>{const e={roleId:2,search:o||null,statusId:"true"===f||"false"!==f&&null,genderId:"101"===c?101:"102"===c?102:null};y((0,v.lE)({finalData:e}))}),[y,o,c,f]);const A=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Doctor Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"},formatter:(e,l)=>(0,I.jsxs)("div",{className:"d-flex align-items-center",children:[(0,I.jsx)("img",{src:null!==l&&void 0!==l&&l.imageUrl?null===l||void 0===l?void 0:l.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"doctor",className:"me-2 dt-round-img"}),(0,I.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,I.jsx)("p",{className:"m-0 table-bold-text",children:null===l||void 0===l?void 0:l.name}),(0,I.jsx)("p",{className:"m-0 table-normal-text",children:null===l||void 0===l?void 0:l.email}),(0,I.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===l||void 0===l?void 0:l.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"mcrn",text:"MCRN",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"genderName",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"status",text:"Status",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,l)=>(0,I.jsx)("p",{className:"mb-0 text-center py-1 custom-width-class ".concat("InActive"===(null===l||void 0===l?void 0:l.status)?"inactive-status":"active-status"),children:"InActive"===(null===l||void 0===l?void 0:l.status)?"Inactive":"Active"})},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,I.jsx)("div",{className:"d-flex justify-content-center",children:(0,I.jsx)(h.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},size:20,onClick:()=>r({data:l,show:!0})})}),headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center"}],C={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,a)=>(0,I.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,I.jsxs)("b",{children:[" ",e," "]})," to ",(0,I.jsx)("b",{children:l})," out of ",(0,I.jsxs)("b",{children:[a," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,I.jsxs)(I.Fragment,{children:[(0,I.jsxs)(m.Z,{className:"user-details-card",children:[(0,I.jsxs)("div",{className:"px-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,I.jsxs)("span",{className:"d-flex align-self-center",children:[(0,I.jsx)(u.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&i(e.target.value)},onChange:e=>{"Enter"===e.key&&i(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing","aria-label":"Search"}),(0,I.jsx)(h.Goc,{size:22,className:"searchbar-icon"})]}),(0,I.jsxs)("div",{className:"d-flex",children:[(0,I.jsx)("div",{className:"mb-2 me-2",children:(0,I.jsxs)("select",{onChange:e=>g(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,I.jsx)("option",{selected:!0,children:"Gender"}),(0,I.jsx)("option",{value:101,children:"Male"}),(0,I.jsx)("option",{value:102,children:"Female"})]})}),(0,I.jsx)("div",{className:"mb-2",children:(0,I.jsxs)("select",{onClick:e=>N(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,I.jsx)("option",{selected:!0,children:"Status"}),(0,I.jsx)("option",{value:"true",children:"Active"}),(0,I.jsx)("option",{value:"false",children:"Inactive"})]})})]})]}),w?(0,I.jsx)(b.Z,{}):(0,I.jsx)("span",{className:"doctor-datatable",children:(0,I.jsx)(x.Z,{columns:A,data:null!==Z&&void 0!==Z&&null!==(l=Z.userRole)&&void 0!==l&&null!==(a=l.getAllUser)&&void 0!==a&&a.data?null===Z||void 0===Z||null===(t=Z.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,j.ZP)(C),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,I.jsx)(F,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function C(e){let{show:l,onClose:a,data:t}=e;const{register:n,handleSubmit:o,setValue:i,control:c,reset:m}=(0,y.cI)(),{user:h}=(0,p.v9)((e=>e.auth)),x=(0,p.I0)();function j(){let e={userId:h.userId,roleId:3};x((0,v.lE)({finalData:e}))}return(0,s.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("currentAddress",(null===t||void 0===t?void 0:t.currentAddress)||""),i("dob",(null===t||void 0===t?void 0:t.dob)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,I.jsx)(I.Fragment,{children:(0,I.jsx)(g.Z,{show:l,onHide:a,size:"lg",children:(0,I.jsxs)(u.Z,{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:3,email:e.email,phoneNumber:e.phoneNumber,firstName:e.firstName,lastName:e.lastName,currentAddress:e.currentAddress,genderId:null===e||void 0===e?void 0:e.genderId,dob:e.dob,password:e.password,staffRoleId:5,image:null};x(t?(0,v.Nq)({finalData:l,onCreateSuccess:j}):(0,v.r4)({finalData:l,onCreateSuccess:j})),a(),m()})),children:[(0,I.jsx)(g.Z.Header,{closeButton:!0,children:(0,I.jsxs)(g.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Patient"]})}),(0,I.jsx)(g.Z.Body,{className:"p-4",children:(0,I.jsxs)(d.Z,{children:[(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"First Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,I.jsxs)(r.Z,{lg:6,children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Gender "}),(0,I.jsxs)(u.Z.Select,{...n("genderId",{required:!t}),children:[(0,I.jsx)("option",{value:"",children:"Select Gender"}),w.sP.map((e=>(0,I.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.value})))]})]}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Password"}),(0,I.jsx)(u.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formDate",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Date "}),(0,I.jsx)(u.Z.Control,{type:"date",placeholder:"dd/mm/yy",size:"lg",...n("dob",{required:!t})})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Email "}),(0,I.jsx)(u.Z.Control,{type:"email",placeholder:"Email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,I.jsx)(y.Qr,{control:c,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,I.jsx)(Z(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Current Address "}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"Type Address here",size:"lg",...n("currentAddress",{required:!t}),maxLength:150})]})})]})}),(0,I.jsxs)(g.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,I.jsx)(f.Z,{onClick:a,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,I.jsxs)(f.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:[t?"Update":"Add"," Patient"]})]})]})})})}var S=a(59513),k=a.n(S),L=a(39126),D=a(72426),P=a.n(D);function z(e){var l,a,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,i]=(0,s.useState)(),[c,g]=(0,s.useState)(null),[f,N]=(0,s.useState)(),Z=(0,p.v9)((e=>e)),{isLoading:w}=(0,p.v9)((e=>e.userRole)),y=(0,p.I0)();(0,s.useEffect)((()=>{const e={roleId:3,search:o,genderId:"101"===f?101:"102"===f?102:null,dob:c?P()(c).format("YYYY-MM-DD"):null};y((0,v.lE)({finalData:e}))}),[y,o,f,c]);const F=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"},formatter:(e,l)=>(0,I.jsxs)("div",{className:"d-flex align-items-center",children:[(0,I.jsx)("img",{src:null!==l&&void 0!==l&&l.imageUrl?null===l||void 0===l?void 0:l.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===l||void 0===l?void 0:l.name),"&background=6045eb&color=fff"),alt:"patient",className:"me-2 dt-round-img"}),(0,I.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,I.jsx)("p",{className:"m-0 table-bold-text",children:null===l||void 0===l?void 0:l.name}),(0,I.jsx)("p",{className:"m-0 table-normal-text",children:null===l||void 0===l?void 0:l.email}),(0,I.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===l||void 0===l?void 0:l.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"genderName",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"dob",text:"DOB",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const l=new Date(e),a=l.getDate().toString().padStart(2,"0"),s=(l.getMonth()+1).toString().padStart(2,"0"),t=l.getFullYear();return"".concat(s,"/").concat(a,"/").concat(t)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,I.jsx)("div",{className:"d-flex justify-content-center",children:(0,I.jsx)(h.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},size:20,onClick:()=>r({data:l,show:!0})})}),headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center"}],A={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,a)=>(0,I.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,I.jsxs)("b",{children:[" ",e," "]})," to ",(0,I.jsx)("b",{children:l})," out of ",(0,I.jsxs)("b",{children:[a," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,I.jsxs)(I.Fragment,{children:[(0,I.jsxs)(m.Z,{className:"user-details-card",children:[(0,I.jsxs)("div",{className:"ps-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,I.jsx)("div",{children:(0,I.jsxs)("span",{className:"d-flex align-self-center",children:[(0,I.jsx)(u.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&i(e.target.value)},onChange:e=>{"Enter"===e.key&&i(e.target.value)},type:"text",placeholder:"Search",className:"mb-3 search-field-spacing","aria-label":"Search"}),(0,I.jsx)(h.Goc,{size:22,className:"searchbar-icon"})]})}),(0,I.jsxs)("div",{className:"mainDiv",children:[(0,I.jsx)("div",{className:"mb-2",children:(0,I.jsxs)("select",{onChange:e=>N(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,I.jsx)("option",{selected:!0,children:"Gender"}),(0,I.jsx)("option",{value:101,children:"Male"}),(0,I.jsx)("option",{value:102,children:"Female"})]})}),(0,I.jsx)(k(),{selected:c,onChange:e=>g(e),dateFormat:"dd MMM yyyy",placeholderText:"DOB",className:"custom-field-picker dr-date-w px-3"}),(0,I.jsx)(L.zlR,{className:"custom-date-icon",size:18,style:{right:"42px"}})]})]}),w?(0,I.jsx)(b.Z,{}):(0,I.jsx)("span",{className:"doctor-datatable",children:(0,I.jsx)(x.Z,{columns:F,data:null!==Z&&void 0!==Z&&null!==(l=Z.userRole)&&void 0!==l&&null!==(a=l.getAllUser)&&void 0!==a&&a.data?null===Z||void 0===Z||null===(t=Z.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,j.ZP)(A),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,I.jsx)(C,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function E(e){let{show:l,onClose:a,data:t}=e;const{register:n,handleSubmit:o,setValue:i,control:c}=(0,y.cI)(),{user:m}=(0,p.v9)((e=>e.auth)),h=(0,p.I0)();function x(){let e={userId:m.userId,roleId:5};h((0,v.lE)({finalData:e}))}return(0,s.useEffect)((()=>{i("firstName",(null===t||void 0===t?void 0:t.firstName)||""),i("lastName",(null===t||void 0===t?void 0:t.lastName)||""),i("email",(null===t||void 0===t?void 0:t.email)||""),i("password",(null===t||void 0===t?void 0:t.password)||""),i("staffRoleId",(null===t||void 0===t?void 0:t.staffRoleId)||""),i("phoneNumber",(null===t||void 0===t?void 0:t.phoneNumber)||""),i("genderId",t?null===t||void 0===t?void 0:t.genderId:"")}),[t]),(0,I.jsx)(I.Fragment,{children:(0,I.jsx)(g.Z,{show:l,onHide:a,size:"md",children:(0,I.jsxs)("form",{onSubmit:o((function(e){const l={userId:t?null===t||void 0===t?void 0:t.userId:0,roleId:5,email:e.email,password:e.password,phoneNumber:e.phoneNumber,firstName:e.firstName,lastName:e.lastName,staffRoleId:e.staffRoleId,genderId:null===e||void 0===e?void 0:e.genderId};h(t?(0,v.Nq)({finalData:l,onCreateSuccess:x}):(0,v.r4)({finalData:l,onCreateSuccess:x})),a()})),children:[(0,I.jsx)(g.Z.Header,{closeButton:!0,children:(0,I.jsxs)(g.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:[t?"Edit":"Add"," Staff"]})}),(0,I.jsx)(g.Z.Body,{className:"p-4",children:(0,I.jsxs)(d.Z,{children:[(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formFirstName",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"First Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"John",size:"lg",...n("firstName",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:6,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formLastName",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Last Name"}),(0,I.jsx)(u.Z.Control,{type:"text",placeholder:"Smith",size:"lg",...n("lastName",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:12,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formBasicEmail",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Email"}),(0,I.jsx)(u.Z.Control,{type:"email",placeholder:"Enter email",size:"lg",...n("email",{required:!t}),maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:12,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formPassword",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Password "}),(0,I.jsx)(u.Z.Control,{type:"password",placeholder:"Password",size:"lg",...n("password",{required:!t}),disabled:t,maxLength:50})]})}),(0,I.jsx)(r.Z,{lg:12,children:(0,I.jsxs)(u.Z.Group,{className:"mb-3",controlId:"formNumber",children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Phone Number"}),(0,I.jsx)(y.Qr,{control:c,name:"phoneNumber",rules:{required:!t},defaultValue:null===t||void 0===t?void 0:t.phoneNumber,render:e=>{let{field:l}=e;return(0,I.jsx)(Z(),{country:"us",value:l.value,onChange:e=>l.onChange("+".concat(e))})}})]})}),(0,I.jsxs)(r.Z,{lg:12,children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Role"}),(0,I.jsxs)(u.Z.Select,{"aria-label":"Select Role",...n("staffRoleId",{required:!t}),defaultValue:null===t||void 0===t?void 0:t.staffRoleId,children:[(0,I.jsx)("option",{value:"",children:"Select Status"}),w.bA.map((e=>(0,I.jsx)("option",{value:null===e||void 0===e?void 0:e.lookupId,children:e.value})))]})]}),(0,I.jsxs)(r.Z,{lg:12,children:[(0,I.jsx)(u.Z.Label,{className:"fw-bold",children:"Gender "}),(0,I.jsxs)(u.Z.Select,{...n("genderId",{required:!t}),children:[(0,I.jsx)("option",{value:"",children:"Select Gender"}),w.sP.map((e=>(0,I.jsx)("option",{value:+(null===e||void 0===e?void 0:e.lookupId),children:e.value})))]})]})]})}),(0,I.jsxs)(g.Z.Footer,{className:"Doctor-Modal-Footer",children:[(0,I.jsx)(f.Z,{onClick:a,className:"Admin-Modal-CancelBtn fw-bold",children:"Cancel"}),(0,I.jsxs)(f.Z,{variant:"primary",type:"submit",className:"Admin-Add-btn fw-bold",children:[t?"Update":"Add"," Staff"]})]})]})})})}function R(e){var l,a,t,d;let{setAddAdmin:r,addAdmin:n}=e;const[o,i]=(0,s.useState)(null),[c,g]=(0,s.useState)(),f=(0,p.v9)((e=>e)),{isLoading:N}=(0,p.v9)((e=>e.userRole)),Z=(0,p.I0)();(0,s.useEffect)((()=>{const e={roleId:5,search:c||null,createdDate:o?P()(o).format("YYYY-MM-DD"):null};Z((0,v.lE)({finalData:e}))}),[Z,c,o]);const w=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"name",text:"Staff Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1",width:"17%"}},{dataField:"email",text:"Email",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"phoneNumber",text:"Phone Number",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const l=new Date(e),a=l.getDate().toString().padStart(2,"0"),s=(l.getMonth()+1).toString().padStart(2,"0"),t=l.getFullYear();return"".concat(s,"/").concat(a,"/").concat(t)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,l)=>(0,I.jsx)("div",{className:"d-flex justify-content-center",children:(0,I.jsx)(h.Hlf,{style:{color:"#1A1A1A",cursor:"pointer"},size:20,onClick:()=>r({data:l,show:!0})})}),headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center"}],y={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,l,a)=>(0,I.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,I.jsxs)("b",{children:[" ",e," "]})," to ",(0,I.jsx)("b",{children:l})," out of ",(0,I.jsxs)("b",{children:[a," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,I.jsxs)(I.Fragment,{children:[(0,I.jsxs)(m.Z,{className:"user-details-card",children:[(0,I.jsxs)("div",{className:"px-4 pt-3 d-flex justify-content-between custom-row align-items-center table-header-border",children:[(0,I.jsxs)("span",{className:"d-flex align-self-center",children:[(0,I.jsx)(u.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&g(e.target.value)},onChange:e=>{"Enter"===e.key&&g(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing",style:{width:"100%"},"aria-label":"Search"}),(0,I.jsx)(h.Goc,{size:22,className:"searchbar-icon"})]}),(0,I.jsxs)("div",{className:"d-flex custom-div-row",children:[(0,I.jsx)(k(),{selected:o,onChange:e=>i(e),dateFormat:"dd MMM yyyy",placeholderText:"Date",className:"custom-field-picker dr-date-w px-3 mb-3"}),(0,I.jsx)(L.zlR,{className:"custom-date-icon",size:18,style:{right:"32px"}})]})]}),N?(0,I.jsx)(b.Z,{}):(0,I.jsx)("span",{className:"doctor-datatable",children:(0,I.jsx)(x.Z,{columns:w,data:null!==f&&void 0!==f&&null!==(l=f.userRole)&&void 0!==l&&null!==(a=l.getAllUser)&&void 0!==a&&a.data?null===f||void 0===f||null===(t=f.userRole)||void 0===t||null===(d=t.getAllUser)||void 0===d?void 0:d.data:[],keyField:"userId",id:"bar",pagination:(0,j.ZP)(y),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"},sort:{dataField:"userId",order:"desc"}})})]}),(0,I.jsx)(E,{data:n.data,show:n.show,onClose:()=>r({show:!1,data:null})})]})}function B(){const[e,l]=(0,s.useState)({data:null,show:!1}),[a,m]=(0,s.useState)("doctor");return(0,I.jsx)("div",{className:"usermanagement-mainclass",children:(0,I.jsx)(t.Z.Container,{id:"left-tabs-example",defaultActiveKey:"doctor",className:"Admin-Tabs-SubMain",onSelect:e=>m(e),children:(0,I.jsxs)(d.Z,{className:"",children:[(0,I.jsx)(r.Z,{lg:9,md:9,sm:8,children:(0,I.jsxs)(n.Z,{variant:"pills",className:"flex-row Nav-MainAdmin",children:[(0,I.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,I.jsxs)(n.Z.Link,{eventKey:"doctor",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,I.jsx)(o.Z5v,{className:"me-2"}),"Doctor"]})}),(0,I.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,I.jsxs)(n.Z.Link,{eventKey:"patient",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,I.jsx)(c.eBc,{className:"me-2"}),"Patient"]})}),(0,I.jsx)(n.Z.Item,{className:"p-2 ps-0",children:(0,I.jsxs)(n.Z.Link,{eventKey:"staff",style:{background:"white",color:"#B3B3B3"},className:"Admin-Tabs-All",children:[(0,I.jsx)(i.VcF,{className:"me-2",size:20}),"Staff"]})})]})}),(0,I.jsx)(r.Z,{lg:3,md:3,sm:4,children:(0,I.jsxs)(t.Z.Content,{children:[(0,I.jsx)(t.Z.Pane,{eventKey:"doctor",children:(0,I.jsx)("div",{className:"d-flex justify-content-end ",children:(0,I.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Doctor"})})}),(0,I.jsx)(t.Z.Pane,{eventKey:"patient",children:(0,I.jsx)("div",{className:"d-flex justify-content-end ",children:(0,I.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Patient"})})}),(0,I.jsx)(t.Z.Pane,{eventKey:"staff",children:(0,I.jsx)("div",{className:"d-flex justify-content-end ",children:(0,I.jsx)("button",{className:" Add-Admin rounded",onClick:()=>l({data:null,show:!0}),children:"Add Staff"})})})]})}),(0,I.jsx)(r.Z,{lg:12,md:12,children:(0,I.jsxs)(t.Z.Content,{children:[(0,I.jsx)(t.Z.Pane,{eventKey:"doctor",children:"doctor"===a&&(0,I.jsx)(A,{addAdmin:e,setAddAdmin:l})}),(0,I.jsx)(t.Z.Pane,{eventKey:"patient",children:"patient"===a&&(0,I.jsx)(z,{addAdmin:e,setAddAdmin:l})}),(0,I.jsx)(t.Z.Pane,{eventKey:"staff",children:"staff"===a&&(0,I.jsx)(R,{addAdmin:e,setAddAdmin:l})})]})})]})})})}}}]);
//# sourceMappingURL=8215.f8be2aa3.chunk.js.map