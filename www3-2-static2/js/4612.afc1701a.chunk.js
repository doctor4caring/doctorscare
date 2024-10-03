"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[4612],{52218:(e,a,t)=>{t.r(a),t.d(a,{default:()=>S});var s=t(72791),l=t(89743),n=t(2677),r=t(95070),o=t(36638),c=t(7692),i=t(78820),d=t(11087),m=t(2002),p=t(36161),u=t(59513),x=t.n(u),h=t(39126),g=(t(68639),t(59434)),f=t(24278),b=t(46587),j=t(3810),N=t(72426),v=t.n(N),F=t(80184);function y(){const[e,a]=(0,s.useState)(null),[t,u]=(0,s.useState)(null),N=(0,g.I0)(),{allAppointedPatient:y}=(0,g.v9)((e=>null===e||void 0===e?void 0:e.appointment)),{user:S}=(0,g.v9)((e=>e.auth)),{isLoading:w}=(0,g.v9)((e=>e.userRole)),[k,C]=(0,s.useState)();(0,s.useEffect)((()=>{const a={doctorId:null===S||void 0===S?void 0:S.userId,search:k||null,dob:e?v()(e).format("YYYY-MM-DD"):null,gender:t?+t:null};N((0,f.Jl)(a))}),[N,null===S||void 0===S?void 0:S.userId,k,e,t]);const D=[{dataField:"patientId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"patientName",text:"Patient Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,a)=>(0,F.jsxs)("div",{className:"d-flex align-items-center",children:[(0,F.jsx)("img",{src:null!==a&&void 0!==a&&a.imageUrl?null===a||void 0===a?void 0:a.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===a||void 0===a?void 0:a.patientName),"&background=000071&color=fff"),alt:"apt patient",className:"me-2 dt-round-img"}),(0,F.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,F.jsx)("p",{className:"m-0 table-bold-text",children:null===a||void 0===a?void 0:a.patientName}),(0,F.jsx)("p",{className:"m-0 table-normal-text",children:null===a||void 0===a?void 0:a.email}),(0,F.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===a||void 0===a?void 0:a.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"createdDate",text:"Created Date",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const a=new Date(e),t=a.getDate().toString().padStart(2,"0"),s=(a.getMonth()+1).toString().padStart(2,"0"),l=a.getFullYear();return"".concat(s,"/").concat(t,"/").concat(l)}},{dataField:"gender",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"dob",text:"DOB",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>{const a=new Date(e),t=a.getDate().toString().padStart(2,"0"),s=(a.getMonth()+1).toString().padStart(2,"0"),l=a.getFullYear();return"".concat(s,"/").concat(t,"/").concat(l)}},{dataField:"action",text:"Action",sort:!1,formatter:(e,a)=>(0,F.jsxs)(d.rU,{to:j.m.PATIENTS_DETAILS.replace(":patientId",null===a||void 0===a?void 0:a.patientId),className:"table-action",children:[(0,F.jsx)(i.w8I,{})," View"]}),headerStyle:{backgroundColor:"#F1F1F1"}}],I={paginationSize:8,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,a,t)=>(0,F.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[(0,F.jsxs)("b",{children:[" ",e," "]})," to ",(0,F.jsx)("b",{children:a})," out of ",(0,F.jsxs)("b",{children:[t," entries"]})]}),disablePageTitle:!0,sizePerPageList:[{text:"6",value:6}]};return(0,F.jsx)(F.Fragment,{children:(0,F.jsx)(r.Z,{className:"shadow-sm patient-card patient-profile-wrapper custom-loading-h",children:(0,F.jsxs)(F.Fragment,{children:[(0,F.jsxs)(l.Z,{className:"px-4 pt-3 d-flex",children:[(0,F.jsx)(n.Z,{md:3,children:(0,F.jsxs)("span",{className:"d-flex",children:[(0,F.jsx)(o.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&C(e.target.value)},onChange:e=>{"Enter"===e.key&&C(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing","aria-label":"Search"}),(0,F.jsx)(c.Goc,{size:22,className:"searchbar-icon"})]})}),(0,F.jsxs)(n.Z,{md:9,className:"d-flex flex-wrap align-self-center justify-content-end pe-0",children:[(0,F.jsxs)("div",{className:"d-flex mb-2 me-2",children:[(0,F.jsx)(x(),{selected:e,onChange:e=>a(e),dateFormat:"dd MMM yyyy",placeholderText:"D.O.B",className:"custom-field-picker patient-profile-dob-w px-3"}),(0,F.jsx)(h.zlR,{className:"custom-date-icon",size:18,style:{top:"16px"}})]}),(0,F.jsx)("div",{children:(0,F.jsxs)("select",{onChange:e=>u(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,F.jsx)("option",{selected:!0,children:"Gender"}),(0,F.jsx)("option",{value:101,children:"Male"}),(0,F.jsx)("option",{value:102,children:"Female"}),(0,F.jsx)("option",{value:103,children:"Other"})]})})]})]}),w?(0,F.jsx)(b.Z,{}):(0,F.jsx)("span",{className:"doctor-datatable",children:(0,F.jsx)(m.Z,{columns:D,data:y||[],keyField:"patientId",id:"bar",pagination:(0,p.ZP)(I),bordered:!1,wrapperClasses:"table-responsive",selectRow:{mode:"checkbox"}})})]})})})}function S(){return(0,F.jsxs)(F.Fragment,{children:[(0,F.jsx)("h5",{children:"My Patients"}),(0,F.jsx)(l.Z,{className:"my-3",children:(0,F.jsx)(n.Z,{xs:12,children:(0,F.jsx)(y,{})})})]})}},89252:(e,a,t)=>{function s(e,a){e.classList?e.classList.add(a):function(e,a){return e.classList?!!a&&e.classList.contains(a):-1!==(" "+(e.className.baseVal||e.className)+" ").indexOf(" "+a+" ")}(e,a)||("string"===typeof e.className?e.className=e.className+" "+a:e.setAttribute("class",(e.className&&e.className.baseVal||"")+" "+a))}t.d(a,{Z:()=>s})},12946:(e,a,t)=>{function s(e,a){return e.replace(new RegExp("(^|\\s)"+a+"(?:\\s|$)","g"),"$1").replace(/\s+/g," ").replace(/^\s*|\s*$/g,"")}function l(e,a){e.classList?e.classList.remove(a):"string"===typeof e.className?e.className=s(e.className,a):e.setAttribute("class",s(e.className&&e.className.baseVal||"",a))}t.d(a,{Z:()=>l})},27472:(e,a,t)=>{t.d(a,{Z:()=>o});var s=t(72791),l=t(81694),n=t.n(l),r=t(80184);const o=e=>s.forwardRef(((a,t)=>(0,r.jsx)("div",{...a,ref:t,className:n()(a.className,e)})))}}]);
//# sourceMappingURL=4612.afc1701a.chunk.js.map