"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[50],{36004:(e,a,s)=>{s.r(a),s.d(a,{default:()=>b});var t=s(72791),l=s(43360),r=s(95070),o=s(89743),n=s(2677),c=s(36638),i=s(7692),d=s(78820),m=s(57689),f=s(2002),p=s(36161),u=s(80591),x=s(59434),h=s(3810),N=s(80184);function b(){const[e,a]=(0,t.useState)(),[s,b]=(0,t.useState)(null),v=(0,x.I0)(),y=(0,m.s0)(),{getAllUser:j}=(0,x.v9)((e=>e.userRole));const g=[{dataField:"userId",text:"ID",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"patientName",text:"Staff Name",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,a)=>(0,N.jsxs)("div",{className:"d-flex align-items-center",children:[(0,N.jsx)("img",{src:"https://ui-avatars.com/api/?name=".concat("".concat(null===a||void 0===a?void 0:a.firstName," ").concat(null===a||void 0===a?void 0:a.lastName),"&background=6045eb&color=fff"),alt:"patient",className:"me-2",style:{borderRadius:"50%",width:"3.3rem"}}),(0,N.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,N.jsx)("p",{className:"m-0 table-bold-text",children:"".concat(null===a||void 0===a?void 0:a.firstName," ").concat(null===a||void 0===a?void 0:a.lastName)}),(0,N.jsx)("p",{className:"m-0 table-normal-text",children:null===a||void 0===a?void 0:a.email}),(0,N.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===a||void 0===a?void 0:a.phoneNumber})]})]})},{dataField:"staffRole",text:"Role",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"genderName",text:"Gender",sort:!0,headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"action",text:"Action",sort:!1,formatter:(e,a)=>(0,N.jsxs)(l.Z,{onClick:()=>{return e=a,void y(h.m.STAFF_CHAT.replace(":staffId",null===e||void 0===e?void 0:e.userId),{state:{staffData:e}});var e},className:"text-decoration-none table-action",style:{background:"transparent",borderColor:"transparent"},children:[(0,N.jsx)(d.LLl,{})," Chat"]}),headerStyle:{backgroundColor:"#F1F1F1"}}],F={paginationSize:10,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:!1,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,a,s)=>(0,N.jsxs)("span",{className:"react-bootstrap-table-pagination-total",children:[e," to ",a," out of ",s," entries"]}),disablePageTitle:!0,sizePerPageList:[{text:"10",value:10}]};return(0,t.useEffect)((()=>{const a={roleId:5,search:e,staffRoleId:s?+s:null};v((0,u.lE)({finalData:a}))}),[v,e,s]),(0,N.jsxs)("div",{className:"staff_main",children:[(0,N.jsx)("h5",{children:"Staff"}),(0,N.jsx)(r.Z,{children:(0,N.jsxs)(r.Z.Body,{className:"p-0 Card-Body-Height",children:[(0,N.jsxs)(o.Z,{className:" px-4 pt-3",children:[(0,N.jsx)(n.Z,{md:3,children:(0,N.jsxs)("span",{className:"d-flex align-self-center",children:[(0,N.jsx)(c.Z.Control,{onKeyDown:e=>{"Enter"===e.key&&a(e.target.value)},onChange:e=>{"Enter"===e.key&&a(e.target.value)},type:"text",placeholder:"Search",className:"me-2 mb-3 search-field-spacing","aria-label":"Search"}),(0,N.jsx)(i.Goc,{size:22,className:"searchbar-icon"})]})}),(0,N.jsx)(n.Z,{md:9,className:"d-flex flex-wrap align-self-center justify-content-end",children:(0,N.jsx)("div",{className:"d-flex mb-2 mr-2",children:(0,N.jsxs)("select",{onChange:e=>b(e.target.value),className:"form-select pe-5","aria-label":"Default select example",children:[(0,N.jsx)("option",{selected:!0,children:"Role"}),(0,N.jsx)("option",{value:6,children:"Nurse"}),(0,N.jsx)("option",{value:7,children:"Receptionist"})]})})})]}),(0,N.jsx)("span",{className:"doctor-datatable",children:(0,N.jsx)(f.Z,{columns:g,data:null!==j&&void 0!==j&&j.data?null===j||void 0===j?void 0:j.data:[],keyField:"id",id:"bar",pagination:(0,p.ZP)(F),bordered:!1,wrapperClasses:"table-responsive",className:"selection-cell-header "})})]})})]})}},89252:(e,a,s)=>{function t(e,a){e.classList?e.classList.add(a):function(e,a){return e.classList?!!a&&e.classList.contains(a):-1!==(" "+(e.className.baseVal||e.className)+" ").indexOf(" "+a+" ")}(e,a)||("string"===typeof e.className?e.className=e.className+" "+a:e.setAttribute("class",(e.className&&e.className.baseVal||"")+" "+a))}s.d(a,{Z:()=>t})},12946:(e,a,s)=>{function t(e,a){return e.replace(new RegExp("(^|\\s)"+a+"(?:\\s|$)","g"),"$1").replace(/\s+/g," ").replace(/^\s*|\s*$/g,"")}function l(e,a){e.classList?e.classList.remove(a):"string"===typeof e.className?e.className=t(e.className,a):e.setAttribute("class",t(e.className&&e.className.baseVal||"",a))}s.d(a,{Z:()=>l})},11701:(e,a,s)=>{s.d(a,{Ed:()=>r,UI:()=>l,XW:()=>o});var t=s(72791);function l(e,a){let s=0;return t.Children.map(e,(e=>t.isValidElement(e)?a(e,s++):e))}function r(e,a){let s=0;t.Children.forEach(e,(e=>{t.isValidElement(e)&&a(e,s++)}))}function o(e,a){return t.Children.toArray(e).some((e=>t.isValidElement(e)&&e.type===a))}},36638:(e,a,s)=>{s.d(a,{Z:()=>D});var t=s(81694),l=s.n(t),r=s(52007),o=s.n(r),n=s(72791),c=s(80184);const i={type:o().string,tooltip:o().bool,as:o().elementType},d=n.forwardRef(((e,a)=>{let{as:s="div",className:t,type:r="valid",tooltip:o=!1,...n}=e;return(0,c.jsx)(s,{...n,ref:a,className:l()(t,"".concat(r,"-").concat(o?"tooltip":"feedback"))})}));d.displayName="Feedback",d.propTypes=i;const m=d;var f=s(84934),p=s(10162);const u=n.forwardRef(((e,a)=>{let{id:s,bsPrefix:t,className:r,type:o="checkbox",isValid:i=!1,isInvalid:d=!1,as:m="input",...u}=e;const{controlId:x}=(0,n.useContext)(f.Z);return t=(0,p.vE)(t,"form-check-input"),(0,c.jsx)(m,{...u,ref:a,type:o,id:s||x,className:l()(r,t,i&&"is-valid",d&&"is-invalid")})}));u.displayName="FormCheckInput";const x=u,h=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,htmlFor:r,...o}=e;const{controlId:i}=(0,n.useContext)(f.Z);return s=(0,p.vE)(s,"form-check-label"),(0,c.jsx)("label",{...o,ref:a,htmlFor:r||i,className:l()(t,s)})}));h.displayName="FormCheckLabel";const N=h;var b=s(11701);const v=n.forwardRef(((e,a)=>{let{id:s,bsPrefix:t,bsSwitchPrefix:r,inline:o=!1,reverse:i=!1,disabled:d=!1,isValid:u=!1,isInvalid:h=!1,feedbackTooltip:v=!1,feedback:y,feedbackType:j,className:g,style:F,title:w="",type:C="checkbox",label:k,children:I,as:R="input",...Z}=e;t=(0,p.vE)(t,"form-check"),r=(0,p.vE)(r,"form-switch");const{controlId:S}=(0,n.useContext)(f.Z),E=(0,n.useMemo)((()=>({controlId:s||S})),[S,s]),P=!I&&null!=k&&!1!==k||(0,b.XW)(I,N),L=(0,c.jsx)(x,{...Z,type:"switch"===C?"checkbox":C,ref:a,isValid:u,isInvalid:h,disabled:d,as:R});return(0,c.jsx)(f.Z.Provider,{value:E,children:(0,c.jsx)("div",{style:F,className:l()(g,P&&t,o&&"".concat(t,"-inline"),i&&"".concat(t,"-reverse"),"switch"===C&&r),children:I||(0,c.jsxs)(c.Fragment,{children:[L,P&&(0,c.jsx)(N,{title:w,children:k}),y&&(0,c.jsx)(m,{type:j,tooltip:v,children:y})]})})})}));v.displayName="FormCheck";const y=Object.assign(v,{Input:x,Label:N});s(42391);const j=n.forwardRef(((e,a)=>{let{bsPrefix:s,type:t,size:r,htmlSize:o,id:i,className:d,isValid:m=!1,isInvalid:u=!1,plaintext:x,readOnly:h,as:N="input",...b}=e;const{controlId:v}=(0,n.useContext)(f.Z);return s=(0,p.vE)(s,"form-control"),(0,c.jsx)(N,{...b,type:t,size:o,ref:a,readOnly:h,id:i||v,className:l()(d,x?"".concat(s,"-plaintext"):s,r&&"".concat(s,"-").concat(r),"color"===t&&"".concat(s,"-color"),m&&"is-valid",u&&"is-invalid")})}));j.displayName="FormControl";const g=Object.assign(j,{Feedback:m}),F=n.forwardRef(((e,a)=>{let{className:s,bsPrefix:t,as:r="div",...o}=e;return t=(0,p.vE)(t,"form-floating"),(0,c.jsx)(r,{ref:a,className:l()(s,t),...o})}));F.displayName="FormFloating";const w=F,C=n.forwardRef(((e,a)=>{let{controlId:s,as:t="div",...l}=e;const r=(0,n.useMemo)((()=>({controlId:s})),[s]);return(0,c.jsx)(f.Z.Provider,{value:r,children:(0,c.jsx)(t,{...l,ref:a})})}));C.displayName="FormGroup";const k=C;var I=s(53392);const R=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,id:r,...o}=e;const{controlId:i}=(0,n.useContext)(f.Z);return s=(0,p.vE)(s,"form-range"),(0,c.jsx)("input",{...o,type:"range",ref:a,className:l()(t,s),id:r||i})}));R.displayName="FormRange";const Z=R,S=n.forwardRef(((e,a)=>{let{bsPrefix:s,size:t,htmlSize:r,className:o,isValid:i=!1,isInvalid:d=!1,id:m,...u}=e;const{controlId:x}=(0,n.useContext)(f.Z);return s=(0,p.vE)(s,"form-select"),(0,c.jsx)("select",{...u,size:r,ref:a,className:l()(o,s,t&&"".concat(s,"-").concat(t),i&&"is-valid",d&&"is-invalid"),id:m||x})}));S.displayName="FormSelect";const E=S,P=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,as:r="small",muted:o,...n}=e;return s=(0,p.vE)(s,"form-text"),(0,c.jsx)(r,{...n,ref:a,className:l()(t,s,o&&"text-muted")})}));P.displayName="FormText";const L=P,T=n.forwardRef(((e,a)=>(0,c.jsx)(y,{...e,ref:a,type:"switch"})));T.displayName="Switch";const A=Object.assign(T,{Input:y.Input,Label:y.Label}),V=n.forwardRef(((e,a)=>{let{bsPrefix:s,className:t,children:r,controlId:o,label:n,...i}=e;return s=(0,p.vE)(s,"form-floating"),(0,c.jsxs)(k,{ref:a,className:l()(t,s),controlId:o,...i,children:[r,(0,c.jsx)("label",{htmlFor:o,children:n})]})}));V.displayName="FloatingLabel";const z=V,O={_ref:o().any,validated:o().bool,as:o().elementType},_=n.forwardRef(((e,a)=>{let{className:s,validated:t,as:r="form",...o}=e;return(0,c.jsx)(r,{...o,ref:a,className:l()(s,t&&"was-validated")})}));_.displayName="Form",_.propTypes=O;const D=Object.assign(_,{Group:k,Control:g,Floating:w,Check:y,Switch:A,Label:I.Z,Text:L,Range:Z,Select:E,FloatingLabel:z})},84934:(e,a,s)=>{s.d(a,{Z:()=>t});const t=s(72791).createContext({})},53392:(e,a,s)=>{s.d(a,{Z:()=>m});var t=s(81694),l=s.n(t),r=s(72791),o=(s(42391),s(2677)),n=s(84934),c=s(10162),i=s(80184);const d=r.forwardRef(((e,a)=>{let{as:s="label",bsPrefix:t,column:d=!1,visuallyHidden:m=!1,className:f,htmlFor:p,...u}=e;const{controlId:x}=(0,r.useContext)(n.Z);t=(0,c.vE)(t,"form-label");let h="col-form-label";"string"===typeof d&&(h="".concat(h," ").concat(h,"-").concat(d));const N=l()(f,t,m&&"visually-hidden",d&&h);return p=p||x,d?(0,i.jsx)(o.Z,{ref:a,as:"label",className:N,htmlFor:p,...u}):(0,i.jsx)(s,{ref:a,className:N,htmlFor:p,...u})}));d.displayName="FormLabel";const m=d},27472:(e,a,s)=>{s.d(a,{Z:()=>n});var t=s(72791),l=s(81694),r=s.n(l),o=s(80184);const n=e=>t.forwardRef(((a,s)=>(0,o.jsx)("div",{...a,ref:s,className:r()(a.className,e)})))}}]);
//# sourceMappingURL=50.becc3e90.chunk.js.map