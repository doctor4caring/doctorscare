"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[9763],{38859:(e,t,a)=>{a.d(t,{Z:()=>l});a(72791);var s=a(80184);function l(e){let{className:t="me-2",label:a,options:l,onChange:n}=e;return(0,s.jsx)("div",{className:"".concat(t),children:(0,s.jsx)("select",{onChange:n,className:"form-select pe-5","aria-label":"Select ".concat(a),children:l.map((e=>(0,s.jsx)("option",{value:e.value,children:e.label},e.value)))})})}},60842:(e,t,a)=>{a.d(t,{Z:()=>o});a(72791);var s=a(59513),l=a.n(s),n=a(39126),i=(a(68639),a(80184));const o=e=>{let{selectedDateState:t,onChange:a,dateFormat:s="dd MMM yyyy",placeholderText:o="Date",className:r="",datePickerClassName:c="custom-field-picker px-2",useDrDateClass:d=!0,...m}=e;return console.log("disabled",m),(0,i.jsxs)("div",{className:"position-relative d-flex mb-3 ".concat(r),...m,children:[(0,i.jsx)(l(),{selected:t,onChange:a,dateFormat:s,placeholderText:o,className:"".concat(c," ").concat(d?"dr-date-w":"w-100"),disabled:null===m||void 0===m?void 0:m.disabled,minDate:null===m||void 0===m?void 0:m.mindate}),(0,i.jsx)(n.zlR,{size:18,className:"custom__date_icon"})]})}},35100:(e,t,a)=>{a.d(t,{Z:()=>i});a(72791);var s=a(36638),l=a(7692),n=a(80184);function i(e){let{onChange:t,...a}=e;return(0,n.jsxs)("div",{className:"position-relative me-2",children:[(0,n.jsx)(s.Z.Control,{onChange:t,type:"text",placeholder:"Search",className:"search-field-spacing ".concat(a.className),"aria-label":"Search"}),(0,n.jsx)(l.Goc,{size:22,className:"searchbar-icon"})]})}},10386:(e,t,a)=>{a.d(t,{Z:()=>i});var s=a(2002),l=a(36161),n=a(80184);function i(e){const{keyField:t,tableColumns:a,tableData:i,pageNumber:o,totalRecords:r,handlePageChange:c,dataPerPage:d}=e,m={paginationSize:5,pageStartIndex:1,alwaysShowAllBtns:!0,withFirstAndLast:(null===i||void 0===i?void 0:i.length)>5,hideSizePerPage:!0,showTotal:!0,paginationTotalRenderer:(e,t,a)=>(0,n.jsx)("span",{className:"react-bootstrap-table-pagination-total",children:(null===i||void 0===i?void 0:i.length)>0?"".concat(e," to ").concat(t," out of ").concat(a," entries"):null}),disablePageTitle:!0,sizePerPageList:[{text:d,value:d}]};return(0,n.jsx)(s.Z,{keyField:t,headerClasses:"header-class",data:i,columns:a,pagination:(0,l.ZP)({...m,page:o,totalSize:r,onPageChange:c}),noDataIndication:()=>(0,n.jsx)("p",{className:"record-message",children:"No Records to Display"}),remote:!0,onTableChange:()=>{},bordered:!1,wrapperClasses:"table-responsive"})}i.defaultProps={pagination:!0}},15626:(e,t,a)=>{a.d(t,{Z:()=>l});var s=a(72791);const l=function(){let e=arguments.length>0&&void 0!==arguments[0]?arguments[0]:500;const[t,a]=(0,s.useState)(""),l=(0,s.useRef)(null);return[t,(0,s.useCallback)((t=>{l.current&&clearTimeout(l.current),l.current=setTimeout((()=>{l.current=null,a(t.target.value)}),e)}),[e])]}},9763:(e,t,a)=>{a.r(t),a.d(t,{default:()=>L});var s=a(72791),l=a(89743),n=a(2677),i=a(95070),o=a(10857),r=a(13496),c=a(59434),d=a(80184);function m(){const{doctorAppointmentCount:e,isLoading:t,isSuccess:a,isError:s}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.doctorDashboard)),l={series:[void 0===(null===e||void 0===e?void 0:e.patientsPreviewFemalePercentage)?[]:null===e||void 0===e?void 0:e.patientsPreviewFemalePercentage,void 0===(null===e||void 0===e?void 0:e.patientsPreviewMalePercentage)?[]:null===e||void 0===e?void 0:e.patientsPreviewMalePercentage],options:{chart:{type:"donut"},plotOptions:{pie:{donut:{labels:{show:!0,position:"bottom",value:{show:!0,fontSize:"33px",fontWeight:500,color:void 0},total:{show:!0,showAlways:!0,label:"Total Patients",fontSize:"16px",fontWeight:500,color:"#999999",formatter:function(t){return(null===e||void 0===e?void 0:e.totalPatientCount)||0}}}}}},labels:["Female","Male"],colors:["#F26522","#000071"],dataLabels:{enabled:!1},legend:{position:"bottom",fontSize:"16px",fontWeight:"bold",formatter:function(e,t){return e+" "+t.w.globals.series[t.seriesIndex]+"%"}},title:{enabled:!1},tooltip:{shared:!1,y:{formatter:function(e){return e+"%"}}},responsive:[{breakpoint:480,options:{chart:{width:200},legend:{position:"bottom"}}}]}};return(0,d.jsx)(d.Fragment,{children:(0,d.jsx)(i.Z,{className:"h-100",children:(0,d.jsxs)(i.Z.Body,{className:"p-4",children:[(0,d.jsx)(i.Z.Title,{className:"mb-0",children:"Patient Overview"}),t?(0,d.jsx)("p",{className:"my-5 text-center fst-italic",style:{color:"#999999"},children:"Loading..."}):a?(0,d.jsx)(r.Z,{options:l.options,series:l.series,type:"donut",height:280,className:"p-3"}):s?(0,d.jsx)("p",{className:"my-5 text-center text-danger fst-italic",children:"Network Error"}):null]})})})}var p=a(29718),h=a.n(p),x=a(12003);function u(){const{doctorAppointmentCount:e,isLoading:t,isSuccess:a,isError:s}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.doctorDashboard)),l=Math.floor(null===e||void 0===e?void 0:e.appointmentPreviewMalePercentage),n=Math.floor(null===e||void 0===e?void 0:e.appointmentPreviewFemalePercentage),o={chart:{plotBackgroundColor:null,plotBorderWidth:null,plotShadow:!1,type:"pie",height:280},title:{text:" "},tooltip:{pointFormat:"{series.name}: <b>{point.percentage:.1f}%</b>"},accessibility:{point:{valueSuffix:"%"}},plotOptions:{pie:{allowPointSelect:!0,cursor:"pointer",dataLabels:{enabled:!1,style:{fontSize:"20px"}},showInLegend:!0}},colors:["#F26522","#000071"],series:[{name:"Series",colorByPoint:!0,data:[{name:"Female ".concat(n,"%"),y:n,sliced:!0,selected:!0},{name:"Male ".concat(l,"%"),y:l}]}]};return(0,d.jsx)(d.Fragment,{children:(0,d.jsx)(i.Z,{className:"h-100 dr-apt-overview",children:(0,d.jsxs)(i.Z.Body,{className:"p-4",children:[(0,d.jsx)(i.Z.Title,{className:"mb-0",children:"Appointment Overview"}),t?(0,d.jsx)("p",{className:"my-5 text-center fst-italic",style:{color:"#999999"},children:"Loading..."}):a?(0,d.jsx)(x.HighchartsReact,{highcharts:h(),options:o,isPureConfig:!0}):s?(0,d.jsx)("p",{className:"my-5 text-center text-danger fst-italic",children:"Network Error"}):null]})})})}var v=a(43360),g=a(78820),N=a(57689),j=a(11087),f=a(72426),b=a.n(f),y=a(24278),Z=a(84129),w=a(3810),S=a(10386),P=a(15626),C=a(60842),F=a(38859),I=a(35100);const D=[{value:null,label:"Gender"},{value:101,label:"Male"},{value:102,label:"Female"},{value:103,label:"Other"}];function T(){const[e,t]=(0,s.useState)(null),[a,o]=(0,s.useState)(null),[r,m]=(0,s.useState)(1),p=(0,s.useMemo)((()=>3),[]),[h,x]=(0,P.Z)(500),u=(0,c.I0)(),f=(0,N.s0)(),{allAppointedPatient:T,isLoading:k,isSuccess:A,isError:M}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.appointment)),{user:E}=(0,c.v9)((e=>e.auth));(0,s.useEffect)((()=>{const t={pageNo:r,size:p,isPagination:!0,doctorId:null===E||void 0===E?void 0:E.userId,search:h,gender:e?+e:null,dob:a?b()(a).format("YYYY-MM-DD"):null};u((0,y.Jl)(t))}),[u,h,null===E||void 0===E?void 0:E.userId,e,a,r]);const Y=[{dataField:"patientId",text:"ID",headerStyle:{backgroundColor:"#F1F1F1"}},{dataField:"patientName",text:"Patient Name",headerStyle:{backgroundColor:"#F1F1F1"},formatter:(e,t)=>(0,d.jsxs)("div",{className:"d-flex align-items-center",children:[(0,d.jsx)("img",{src:null!==t&&void 0!==t&&t.imageUrl?null===t||void 0===t?void 0:t.imageUrl:"https://ui-avatars.com/api/?name=".concat("".concat(null===t||void 0===t?void 0:t.patientName),"&background=000071&color=fff"),alt:"apt patient",className:"me-2 dt-round-img"}),(0,d.jsxs)("span",{style:{lineHeight:"1.2"},children:[(0,d.jsx)("p",{className:"m-0 table-bold-text",children:null===t||void 0===t?void 0:t.patientName}),(0,d.jsx)("p",{className:"m-0 table-normal-text",children:null===t||void 0===t?void 0:t.email}),(0,d.jsx)("p",{className:"m-0 table-normal-text",style:{color:"#999999"},children:null===t||void 0===t?void 0:t.phoneNumber})]})]})},{dataField:"currentAddress",text:"Location",headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"gender",text:"Gender",headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e||"N/A"},{dataField:"dob",text:"DOB",headerStyle:{backgroundColor:"#F1F1F1"},formatter:e=>e?b()(e).format("DD/MM/YYYY"):"N/A"},{dataField:"action",text:"Action",sort:!1,formatter:(e,t)=>(0,d.jsxs)(j.rU,{to:w.m.PATIENTS_DETAILS.replace(":patientId",null===t||void 0===t?void 0:t.patientId),className:"table-action",children:[(0,d.jsx)(g.w8I,{})," View"," "]}),headerStyle:{backgroundColor:"#F1F1F1"}}];return(0,d.jsx)(d.Fragment,{children:(0,d.jsx)(i.Z,{className:"mb-0 dr-date-wrapper patient-dashboard-table",children:(0,d.jsxs)(i.Z.Body,{className:"p-0",children:[(0,d.jsxs)(l.Z,{className:"px-4 pt-3",children:[(0,d.jsx)(n.Z,{md:4,children:(0,d.jsx)(I.Z,{onChange:x,className:"me-2 mb-3"})}),(0,d.jsxs)(n.Z,{md:8,className:"d-flex flex-wrap align-self-center justify-content-end",children:[(0,d.jsx)(F.Z,{label:"Gender",onChange:e=>t(e.target.value),options:D}),(0,d.jsx)(C.Z,{selectedDateState:a,onChange:e=>o(e),className:"me-2"}),(0,d.jsx)(v.Z,{variant:"outline-secondary",className:"custom-outline-btn mb-3",onClick:()=>f(w.m.PATIENTS),children:"View All"})]})]}),k?(0,d.jsx)(Z.Z,{fullHeight:!0}):A?(0,d.jsx)("span",{className:"doctor-datatable",children:(0,d.jsx)(S.Z,{tableColumns:Y,tableData:null!==T&&void 0!==T&&T.data?null===T||void 0===T?void 0:T.data:[],keyField:"patientId",pageNumber:r,totalRecords:null===T||void 0===T?void 0:T.totalCounts,dataPerPage:p,handlePageChange:(e,t)=>{m(e)}})}):M?(0,d.jsx)("p",{className:"my-5 text-center text-danger fst-italic",children:"Network Error"}):null]})})})}var k=a(59513),A=a.n(k);function M(){var e,t;const[a,l]=(0,s.useState)(null),n=(0,c.I0)(),r=(0,N.s0)(),m=JSON.parse(localStorage.getItem("family_doc_app")),{allAppointment:p,isLoading:h,isSuccess:x,isError:u}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.appointment));return(0,s.useEffect)((()=>{const e={doctorId:null===m||void 0===m?void 0:m.userId,isDashbaordAppointment:!0,startdate:a?b()(a).format("YYYY-MM-DD"):b()(new Date).format("YYYY-MM-DD"),endDate:a?b()(a).format("YYYY-MM-DD"):b()(new Date).format("YYYY-MM-DD"),statusId:202};n((0,y.Qe)(e))}),[n,null===m||void 0===m?void 0:m.userId,a]),(0,d.jsx)(d.Fragment,{children:(0,d.jsx)(i.Z,{className:"py-4 m-0 h-100",children:(0,d.jsxs)(i.Z.Body,{className:"p-0",children:[(0,d.jsxs)("span",{className:"d-flex align-items-center px-4 pb-0 ",children:[(0,d.jsx)("img",{src:o.Z.APPOINTMENT_ICON,alt:"new patient icon",style:{width:"20px"},className:"me-2 color-dk-blue"}),(0,d.jsx)(i.Z.Title,{className:"m-0",children:"Calendar"})]}),(0,d.jsx)(i.Z.Body,{className:"px-0",children:(0,d.jsx)("span",{className:"patient-calendar",children:(0,d.jsx)(A(),{selected:a,onChange:e=>l(e),startDate:a,inline:!0})})}),(0,d.jsxs)("div",{className:"px-3",style:{height:"22rem"},children:[(0,d.jsx)("p",{style:{fontSize:"20px",fontWeight:500},children:"Upcoming Appointment"}),(0,d.jsx)("div",{className:"h-100 no-margin-bottom-last",style:{maxHeight:"19rem",overflowY:"scroll"},children:h?(0,d.jsx)("span",{className:"fst-italic h-100 d-flex justify-content-center align-items-center flex-column",style:{color:"#999999"},children:"Loading..."}):x?(null===p||void 0===p||null===(e=p.data)||void 0===e?void 0:e.length)>0?null===p||void 0===p||null===(t=p.data)||void 0===t?void 0:t.map(((e,t)=>(0,d.jsxs)(i.Z.Body,{className:"mb-3 calendar-card",children:[(0,d.jsx)(i.Z.Title,{style:{fontSize:"24px"},children:null===e||void 0===e?void 0:e.reasonForAppoinment}),(0,d.jsxs)("div",{className:"d-flex align-items-center",children:[(0,d.jsxs)("span",{className:"me-3 apt-inner-card p-2 d-flex align-items-center flex-column",children:[(0,d.jsx)("p",{style:{fontSize:"26px",fontWeight:600},className:"mb-0",children:b()(null===e||void 0===e?void 0:e.appointmentDate).format("MMM DD")}),(0,d.jsxs)("p",{className:"m-0 table-normal-text",children:[(0,d.jsx)(g.Gtc,{className:"me-2",style:{color:"#999999"}}),null===e||void 0===e?void 0:e.appointmentStartTime]})]}),(0,d.jsxs)("span",{style:{lineHeight:"1.4"},children:[(0,d.jsxs)("p",{className:"m-0",style:{fontSize:"18px"},children:[(0,d.jsx)("span",{className:"font-weight-600",children:"Patient:"})," ",null===e||void 0===e?void 0:e.patientName]}),(0,d.jsxs)("p",{className:"m-0",style:{fontSize:"18px"},children:[(0,d.jsx)("span",{className:"font-weight-600",children:"Doctor:"})," ",null===e||void 0===e?void 0:e.doctorName]})]})]}),(0,d.jsx)(v.Z,{className:"mt-4 w-100",style:{backgroundColor:"#000071",border:"0px"},onClick:()=>{return t=e,localStorage.setItem("slotDescription",JSON.stringify(t)),void r(w.m.TELE_CONSULTATION);var t},children:"Join Appointment"},null===e||void 0===e?void 0:e.appointmentId)]}))):(0,d.jsxs)("div",{className:"h-100 py-2 d-flex justify-content-center align-items-center flex-column",children:[(0,d.jsx)("img",{src:o.Z.UPCOMING_APPOINTMENT_ICON,alt:"upcoming appointment"}),(0,d.jsx)("p",{className:"mb-0 mt-2 color-99 text-center",style:{fontSize:"20px",fontWeight:400,width:"54%"},children:"No appointment scheduled"})]}):u?(0,d.jsx)("span",{className:"text-danger fst-italic h-100 d-flex justify-content-center align-items-center flex-column",children:"Network Error"}):null})]})]})})})}var E=a(28063),Y=a(88135);function O(e){let{isModalOpen:t}=e;const a=(0,N.s0)();return(0,d.jsxs)(Y.Z,{size:"lg",show:t,backdrop:"static",children:[(0,d.jsx)(Y.Z.Header,{children:(0,d.jsx)(Y.Z.Title,{style:{fontSize:"19px",fontWeight:"bold"},children:"Signature Required"})}),(0,d.jsxs)(Y.Z.Body,{className:"p-4 text-center",children:[(0,d.jsx)("h5",{className:"fw-bold",children:"You don't have any signature added"}),(0,d.jsx)("p",{className:"m-0",children:"We would love to serve you please proceed by clicking the button below and add your signature"})]}),(0,d.jsx)(Y.Z.Footer,{className:"d-flex justify-content-center",children:(0,d.jsx)(v.Z,{onClick:()=>a("".concat(w.m.PROFILE,"?profile=signature")),className:"Admin-Add-btn fw-bold",children:"Add Signature"})})]})}function L(){const[e,t]=(0,s.useState)(!1),a=JSON.parse(localStorage.getItem("family_doc_app")),{doctorAppointmentCount:r,isLoading:p,isSuccess:h,isError:x}=(0,c.v9)((e=>null===e||void 0===e?void 0:e.doctorDashboard)),v=(0,c.I0)();return(0,s.useEffect)((()=>{!1===(null===a||void 0===a?void 0:a.doctorSignature)&&t(!0)}),[]),(0,s.useEffect)((()=>{v((0,E.AN)())}),[v]),(0,d.jsxs)(d.Fragment,{children:[(0,d.jsxs)(l.Z,{className:"main-row",children:[(0,d.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,d.jsx)(i.Z,{className:"h-100",children:(0,d.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,d.jsxs)("span",{children:[(0,d.jsx)(i.Z.Title,{children:"Total Appointments"}),p?(0,d.jsx)("span",{className:"fst-italic",style:{color:"#999999"},children:"Loading..."}):h?(0,d.jsx)("h3",{className:"mb-0",children:r&&(null===r||void 0===r?void 0:r.totalAppointments)}):x?(0,d.jsx)("span",{className:"text-danger fst-italic",children:"Network Error"}):null]}),(0,d.jsx)("img",{src:o.Z.APPOINTMENT_ICON,alt:"appointment icon",className:"color-dk-blue"})]})})}),(0,d.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,d.jsx)(i.Z,{className:"h-100",children:(0,d.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,d.jsxs)("span",{children:[(0,d.jsx)(i.Z.Title,{children:"New Patients"}),p?(0,d.jsx)("span",{className:"fst-italic",style:{color:"#999999"},children:"Loading..."}):h?(0,d.jsx)("h3",{className:"mb-0",children:r&&(null===r||void 0===r?void 0:r.newPatients)}):x?(0,d.jsx)("span",{className:"text-danger fst-italic",children:"Network Error"}):null]}),(0,d.jsx)("img",{src:o.Z.NEW_PATIENT_ICON,alt:"new patient icon",className:"color-dk-blue"})]})})}),(0,d.jsx)(n.Z,{sm:4,xs:12,className:"xs-margin-bottom",children:(0,d.jsx)(i.Z,{className:"h-100",children:(0,d.jsxs)(i.Z.Body,{className:"d-flex justify-content-between align-items-center p-4 display-column-reverse",children:[(0,d.jsxs)("span",{children:[(0,d.jsx)(i.Z.Title,{children:"Previous Patients"}),p?(0,d.jsx)("span",{className:"fst-italic",style:{color:"#999999"},children:"Loading..."}):h?(0,d.jsx)("h3",{className:"mb-0",children:r&&(null===r||void 0===r?void 0:r.previousPatient)}):x?(0,d.jsx)("span",{className:"text-danger fst-italic",children:"Network Error"}):null]}),(0,d.jsx)("img",{src:o.Z.NEW_PATIENT_ICON,alt:"new patient icon",className:"color-dk-blue"})]})})})]}),(0,d.jsxs)(l.Z,{className:"my-3",children:[(0,d.jsx)(n.Z,{xl:8,xs:12,children:(0,d.jsxs)(l.Z,{children:[(0,d.jsx)(n.Z,{sm:6,xs:12,className:"mb-3",children:(0,d.jsx)(m,{})}),(0,d.jsx)(n.Z,{sm:6,xs:12,className:"mb-3",children:(0,d.jsx)(u,{})}),(0,d.jsx)(n.Z,{xs:12,children:(0,d.jsx)(T,{})})]})}),(0,d.jsx)(n.Z,{xl:4,xs:12,children:(0,d.jsx)(l.Z,{className:"h-100",children:(0,d.jsx)(n.Z,{xs:12,children:(0,d.jsx)(M,{})})})})]}),(0,d.jsx)(O,{isModalOpen:e})]})}}}]);
//# sourceMappingURL=9763.b02de196.chunk.js.map