"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[8875],{60842:(e,a,t)=>{t.d(a,{Z:()=>r});t(72791);var o=t(59513),l=t.n(o),n=t(39126),s=(t(68639),t(80184));const r=e=>{let{selectedDateState:a,onChange:t,dateFormat:o="dd MMM yyyy",placeholderText:r="Date",className:i="",datePickerClassName:d="custom-field-picker px-2",useDrDateClass:c=!0,...m}=e;return console.log("disabled",m),(0,s.jsxs)("div",{className:"position-relative d-flex mb-3 ".concat(i),...m,children:[(0,s.jsx)(l(),{selected:a,onChange:t,dateFormat:o,placeholderText:r,className:"".concat(d," ").concat(c?"dr-date-w":"w-100"),disabled:null===m||void 0===m?void 0:m.disabled,minDate:null===m||void 0===m?void 0:m.mindate}),(0,s.jsx)(n.zlR,{size:18,className:"custom__date_icon"})]})}},35100:(e,a,t)=>{t.d(a,{Z:()=>s});t(72791);var o=t(36638),l=t(7692),n=t(80184);function s(e){let{onChange:a,...t}=e;return(0,n.jsxs)("div",{className:"position-relative me-2",children:[(0,n.jsx)(o.Z.Control,{onChange:a,type:"text",placeholder:"Search",className:"search-field-spacing ".concat(t.className),"aria-label":"Search"}),(0,n.jsx)(l.Goc,{size:22,className:"searchbar-icon"})]})}},10386:(e,a,t)=>{t.d(a,{Z:()=>s});var o=t(2002),l=t(36161),n=t(80184);function s(e){const{keyField:a,tableColumns:t,tableData:s,pageNumber:r,totalRecords:i,handlePageChange:d,dataPerPage:c}=e,m={paginationSize:5,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:(null===s||void 0===s?void 0:s.length)>5,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,a,t)=>(0,n.jsx)("span",{className:"react-bootstrap-table-pagination-total",children:(null===s||void 0===s?void 0:s.length)>0?"".concat(e," to ").concat(a," out of ").concat(t," entries"):null}),disablePageTitle:!0,sizePerPageList:[{text:c,value:c}]};return(0,n.jsx)(o.Z,{keyField:a,headerClasses:"header-class",data:s,columns:t,pagination:(0,l.ZP)({...m,page:r,totalSize:i,onPageChange:d}),noDataIndication:()=>(0,n.jsx)("p",{className:"record-message",children:"No Records to Display"}),remote:!0,onTableChange:()=>{},bordered:!1,wrapperClasses:"table-responsive"})}s.defaultProps={pagination:!0}},28875:(e,a,t)=>{t.r(a),t.d(a,{default:()=>S});var o=t(72791),l=t(95070),n=t(89743),s=t(2677),r=t(88135),i=t(43360),d=t(2002),c=t(24278),m=t(59434),u=t(49739),p=t(15626),h=t(80591),v=t(35100),g=t(80184);const x=[{dataField:"doctorList",headerAttrs:{hidden:!0},formatter:(e,a)=>(0,g.jsxs)("div",{className:"d-flex align-items-center",children:[(0,g.jsx)("img",{src:null!==a&&void 0!==a&&a.imageUrl?null===a||void 0===a?void 0:a.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===a||void 0===a?void 0:a.name),"&background=000071&color=fff"),alt:"doctor",className:"me-2 dt-round-img"}),(0,g.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,g.jsx)("p",{className:"m-0 table-bold-text",children:null===a||void 0===a?void 0:a.name}),(0,g.jsx)("p",{className:"m-0 table-normal-text",children:null===a||void 0===a?void 0:a.email}),(0,g.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===a||void 0===a?void 0:a.phoneNumber})]})]})}];function b(e){let{show:a,onClose:t,pageNumber:l,pageSize:n,doctorData:s}=e;const[b,f]=(0,o.useState)(null),[j,N]=(0,o.useState)([]),[y,C]=(0,p.Z)(500),{getAllUser:S,isLoading:F}=(0,m.v9)((e=>null===e||void 0===e?void 0:e.userRole)),Z=(0,m.I0)(),w={mode:"radio",clickToSelect:!0,onSelect:e=>{f(e)}};(0,o.useEffect)((()=>{const e={roleId:2,search:y||null};Z((0,h.lE)({finalData:e}))}),[Z,y]),(0,o.useEffect)((()=>{if(s){var e;const a=null===S||void 0===S||null===(e=S.data)||void 0===e?void 0:e.filter((e=>(null===e||void 0===e?void 0:e.userId)!==(null===s||void 0===s?void 0:s.doctorId)));N(a)}}),[null===S||void 0===S?void 0:S.data,s]);const D=()=>{t();const e={pageNo:l,size:n,isPagination:!0};Z((0,c.Qe)(e)),f(null)};return(0,g.jsxs)(r.Z,{show:a,onHide:t,size:"lg",backdrop:"static",children:[(0,g.jsx)(r.Z.Header,{closeButton:!0,children:(0,g.jsx)(r.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:"Doctors"})}),(0,g.jsxs)(r.Z.Body,{children:[(0,g.jsx)("label",{className:"header-user-text mb-2",children:"Search Doctor"}),(0,g.jsx)(v.Z,{onChange:C,className:"mb-3"}),(0,g.jsx)("span",{className:"doctors-apt-modal-table",children:(0,g.jsx)(d.Z,{columns:x,data:j||[],keyField:"userId",bordered:!1,wrapperClasses:"table-responsive",selectRow:w})})]}),(0,g.jsx)(r.Z.Footer,{children:(0,g.jsx)(i.Z,{variant:"primary",className:"Admin-Add-btn fw-bold w-100 ".concat(F&&"disabled"),onClick:()=>(()=>{const e={appointmentId:null===s||void 0===s?void 0:s.appointmentId,doctorId:null===b||void 0===b?void 0:b.userId};Z((0,c.Cn)({finalData:e,moveToNext:D}))})(),disabled:!b,children:F?(0,g.jsx)(u.Z,{color:"white",size:25,className:"d-flex m-auto"}):"Assign"})})]})}var f=t(72426),j=t.n(f),N=t(10386),y=t(84129),C=t(60842);function S(){const[e,a]=(0,o.useState)(null),[t,r]=(0,o.useState)([]),[i,d]=(0,o.useState)(1),u=(0,o.useMemo)((()=>10),[]),[h,x]=(0,o.useState)(!1),[f,S]=(0,p.Z)(500),F=(0,m.I0)(),{allAppointment:Z,isLoading:w,isError:D,isSuccess:k}=(0,m.v9)((e=>e.appointment));(0,o.useEffect)((()=>{const a={pageNo:i,size:u,isPagination:!0,search:f||null,appointmentDate:e?j()(e).format("YYYY-MM-DD"):null};F((0,c.Qe)(a))}),[F,f,e,i]);const P=[{dataField:"appointmentId",text:"ID",headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"doctorName",text:"Doctor Name",headerStyle:{backgroundColor:"#F1F1F1",width:"17%"},formatter:(e,a)=>(0,g.jsxs)("div",{className:"d-flex align-items-center",children:[(0,g.jsx)("img",{src:null!==a&&void 0!==a&&a.imageUrl?null===a||void 0===a?void 0:a.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===a||void 0===a?void 0:a.doctorName),"&background=000071&color=fff"),alt:"doctor",className:"me-2 dt-round-img"}),(0,g.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,g.jsx)("p",{className:"m-0 table-bold-text",children:null===a||void 0===a?void 0:a.doctorName}),(0,g.jsx)("p",{className:"m-0 table-normal-text",children:null===a||void 0===a?void 0:a.email}),(0,g.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===a||void 0===a?void 0:a.phoneNumber})]})]})},{dataField:"appointmentDate",text:"Date",headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e?j()(e).format("DD/MM/YYYY"):"N/A"},{dataField:"appointmentStartTime",text:"Time",headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"actions",text:"Actions",sort:!1,headerStyle:{backgroundColor:"#F1F1F1"},headerAlign:"center",formatter:(e,a)=>(0,g.jsx)("p",{className:"m-0 py-1 action-data",onClick:()=>{r(a),x(!0)},children:"Unassign"})}];return(0,g.jsxs)("div",{className:"doctor-patient-paymentdetails",children:[(0,g.jsx)("h5",{children:"Doctors Appointment"}),(0,g.jsxs)(l.Z,{className:"patient-details-card superadmin-date-wrapper",children:[(0,g.jsxs)(n.Z,{className:"pt-3 px-4",children:[(0,g.jsx)(s.Z,{md:3,children:(0,g.jsx)(v.Z,{onChange:S})}),(0,g.jsx)(s.Z,{md:9,className:"d-flex flex-wrap align-self-center justify-content-end",children:(0,g.jsx)(C.Z,{selectedDateState:e,onChange:e=>a(e)})})]}),w?(0,g.jsx)(y.Z,{fullHeight:!0}):k?(0,g.jsx)("span",{className:"doctors-apt-table doctor-datatable",children:(0,g.jsx)(N.Z,{tableColumns:P,tableData:(null===Z||void 0===Z?void 0:Z.data)||[],keyField:"appointmentId",pageNumber:i,totalRecords:null===Z||void 0===Z?void 0:Z.totalCounts,dataPerPage:u,handlePageChange:(e,a)=>{d(e)}})}):D?(0,g.jsx)("p",{className:"my-5 text-center text-danger fst-italic",children:"Network Error"}):null]}),(0,g.jsx)(b,{show:h,onClose:()=>x(!1),pageSize:u,pageNumber:i,doctorData:t})]})}},15626:(e,a,t)=>{t.d(a,{Z:()=>l});var o=t(72791);const l=function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:500;const[a,t]=(0,o.useState)(""),l=(0,o.useRef)(null);return[a,(0,o.useCallback)((a=>{l.current&&clearTimeout(l.current),l.current=setTimeout((()=>{l.current=null,t(a.target.value)}),e)}),[e])]}},49739:(e,a,t)=>{t.d(a,{Z:()=>d});var o=t(72791),l=t(75617),n=t(6707),s=function(){return s=Object.assign||function(e){for(var a,t=1,o=arguments.length;t<o;t++)for(var l in a=arguments[t])Object.prototype.hasOwnProperty.call(a,l)&&(e[l]=a[l]);return e},s.apply(this,arguments)},r=function(e,a){var t={};for(var o in e)Object.prototype.hasOwnProperty.call(e,o)&&a.indexOf(o)<0&&(t[o]=e[o]);if(null!=e&&"function"===typeof Object.getOwnPropertySymbols){var l=0;for(o=Object.getOwnPropertySymbols(e);l<o.length;l++)a.indexOf(o[l])<0&&Object.prototype.propertyIsEnumerable.call(e,o[l])&&(t[o[l]]=e[o[l]])}return t},i=(0,n.i)("ClipLoader","0% {transform: rotate(0deg) scale(1)} 50% {transform: rotate(180deg) scale(0.8)} 100% {transform: rotate(360deg) scale(1)}","clip");const d=function(e){var a=e.loading,t=void 0===a||a,n=e.color,d=void 0===n?"#000000":n,c=e.speedMultiplier,m=void 0===c?1:c,u=e.cssOverride,p=void 0===u?{}:u,h=e.size,v=void 0===h?35:h,g=r(e,["loading","color","speedMultiplier","cssOverride","size"]),x=s({background:"transparent !important",width:(0,l.E)(v),height:(0,l.E)(v),borderRadius:"100%",border:"2px solid",borderTopColor:d,borderBottomColor:"transparent",borderLeftColor:d,borderRightColor:d,display:"inline-block",animation:"".concat(i," ").concat(.75/m,"s 0s infinite linear"),animationFillMode:"both"},p);return t?o.createElement("span",s({style:x},g)):null}}}]);
//# sourceMappingURL=8875.842d8175.chunk.js.map