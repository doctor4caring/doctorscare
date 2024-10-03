"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3962],{43962:(e,n,d)=>{d.r(n),d.d(n,{default:()=>M});var l=d(72791),o=d(90575),i=d(38217),t=d(52720),s=d(74332),a=d(57689),v=d(3810),u=d(95070),p=d(1444),r=d(36638),m=d(88135),c=d(43360),f=d(4053),x=d(72426),h=d.n(x),D=d(59434),_=d(24278),g=d(80184);function M(){var e,n,d,x,M,P,A,j,I,Y,N,S,T,b,k,y,w,Z,C,E,B,F,U,W;const z=(0,l.useRef)(),O=(0,D.I0)(),R=JSON.parse(localStorage.getItem("family_doc_app")),G=(0,a.s0)(),[H,L]=(0,l.useState)(),[J,Q]=(0,l.useState)(null),{allAppointment:V}=(0,D.v9)((e=>e.appointment)),q=null===V||void 0===V?void 0:V.map((e=>{var n;return{doctorId:null===e||void 0===e?void 0:e.doctorId,doctorName:null===e||void 0===e?void 0:e.doctorName,patientName:null===e||void 0===e?void 0:e.patientName,vonageSessionId:null===e||void 0===e?void 0:e.vonageSessionId,statusId:null===e||void 0===e?void 0:e.statusId,status:null===e||void 0===e?void 0:e.status,imageUrl:null===e||void 0===e?void 0:e.imageUrl,isDoctorMissed:null===e||void 0===e?void 0:e.isDoctorMissed,isPatientMissed:null===e||void 0===e?void 0:e.isPatientMissed,scheduleId:null===e||void 0===e?void 0:e.scheduleId,appointmentDate:null===e||void 0===e?void 0:e.appointmentDate,patientId:null===e||void 0===e?void 0:e.patientId,appointmentStartTime:null===e||void 0===e?void 0:e.appointmentStartTime,appointmentEndTime:null===e||void 0===e?void 0:e.appointmentEndTime,reasonForAppoinment:null===e||void 0===e?void 0:e.reasonForAppoinment,appointmentId:null===e||void 0===e?void 0:e.appointmentId,image:null===e||void 0===e?void 0:e.image,start:null===e||void 0===e||null===(n=e.appointmentDate)||void 0===n?void 0:n.split("T")[0]}})),[K,X]=(0,l.useState)(!1),[$,ee]=(0,l.useState)(!1),[ne,de]=(0,l.useState)(!1),[le,oe]=(0,l.useState)(null);(0,l.useEffect)((()=>{if(le){var e,n,d,l;let p=h()(new Date),r=new Date("".concat(h()(null===le||void 0===le||null===(e=le._def)||void 0===e||null===(n=e.extendedProps)||void 0===n?void 0:n.appointmentDate).format("YYYY-MM-DD"),"T").concat(h()(null===le||void 0===le||null===(d=le._def)||void 0===d||null===(l=d.extendedProps)||void 0===l?void 0:l.appointmentStartTime,"hh:mm A").format("HH:mm:ss"))),m=h().duration(h()(r).diff(p)).asMinutes();ee(m<10&&m>-15);let c=!1;var o,i,t,s,a,v,u;if(m<=60)c=!1;else(202===(null===le||void 0===le||null===(o=le._def)||void 0===o?void 0:o.extendedProps.statusId)||205===(null===le||void 0===le||null===(i=le._def)||void 0===i||null===(t=i.extendedProps)||void 0===t?void 0:t.statusId)&&!0===(null===le||void 0===le||null===(s=le._def)||void 0===s||null===(a=s.extendedProps)||void 0===a?void 0:a.isDoctorMissed)&&!1===(null===le||void 0===le||null===(v=le._def)||void 0===v||null===(u=v.extendedProps)||void 0===u?void 0:u.isPatientMissed))&&(c=!0);de(c)}else ee(!1)}),[le]);const ie=function(){var e,n;let d=arguments.length>0&&void 0!==arguments[0]?arguments[0]:new Date(null===le||void 0===le||null===(e=le._def)||void 0===e||null===(n=e.extendedProps)||void 0===n?void 0:n.appointmentDate),l=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"en-US";return null===d||void 0===d?void 0:d.toLocaleDateString(l,{weekday:"long"})}();return(0,l.useEffect)((()=>{const e={patientId:null===R||void 0===R?void 0:R.userId,month:+h()(H).format("M"),statusId:"205"===J?205:"204"===J?204:"206"===J?206:"203"===J?203:"201"===J?201:null};O((0,_.Qe)(e))}),[O,H,null===R||void 0===R?void 0:R.userId,J]),(0,g.jsx)(u.Z,{className:"custom-full-calendar",children:(0,g.jsxs)(u.Z.Body,{className:"p-4",style:{borderRadius:"12px"},children:[(0,g.jsx)("span",{className:"fc-header-dropdown",children:(0,g.jsxs)(p.Z,{children:[(0,g.jsx)(p.Z.Toggle,{variant:"secondary",id:"checkbox-dropdown",children:"Appointments"}),(0,g.jsx)(p.Z.Menu,{children:(0,g.jsx)(r.Z,{children:[{label:"Missed",value:205},{label:"Upcoming",value:204},{label:"Completed",value:206},{label:"Cancelled",value:203},{label:"Pending",value:201}].map((e=>(0,g.jsx)(r.Z.Check,{type:"checkbox",label:e.label,value:e.value,checked:null!==J&&J.includes(e.value),onChange:e=>Q(J===e.target.value?null:e.target.value)},e.value)))})})]})}),(0,g.jsx)("div",{className:"appointment-calender",children:(0,g.jsx)(o.Z,{plugins:[i.Z,t.Z,s.ZP],initialView:"dayGridMonth",headerToolbar:{start:"dayGridMonth,timeGridWeek,timeGridDay",center:"prev,title,next",end:""},ref:z,datesSet:()=>(e=>{var n,d,l;L(null===e||void 0===e||null===(n=e.current)||void 0===n||null===(d=n.calendar)||void 0===d||null===(l=d.currentData)||void 0===l?void 0:l.currentDate)})(z),weekends:!0,events:q,eventContent:e=>{var n,d,l,o,i,t,s,a,v,u,p,r,m,c,f,x,D,_,M,P,A,j,I,Y,N,S;return(0,g.jsx)(g.Fragment,{children:(0,g.jsxs)("div",{className:"appointment-slot-background",style:{backgroundColor:"Booked"===(null===e||void 0===e||null===(n=e.event)||void 0===n||null===(d=n._def)||void 0===d||null===(l=d.extendedProps)||void 0===l?void 0:l.status)&&(null===(o=h()(null===e||void 0===e||null===(i=e.event)||void 0===i||null===(t=i._def)||void 0===t||null===(s=t.extendedProps)||void 0===s?void 0:s.appointmentDate))||void 0===o?void 0:o.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"#2269F2":"Missed"===(null===e||void 0===e||null===(a=e.event)||void 0===a||null===(v=a._def)||void 0===v||null===(u=v.extendedProps)||void 0===u?void 0:u.status)?"#F26522":"#44BC19"},children:[(0,g.jsx)("b",{children:"".concat(null===e||void 0===e||null===(p=e.event)||void 0===p||null===(r=p._def)||void 0===r||null===(m=r.extendedProps)||void 0===m?void 0:m.appointmentStartTime," - ").concat(null===e||void 0===e||null===(c=e.event)||void 0===c||null===(f=c._def)||void 0===f||null===(x=f.extendedProps)||void 0===x?void 0:x.appointmentEndTime)}),(0,g.jsx)("p",{className:"m-0",children:"Booked"===(null===e||void 0===e||null===(D=e.event)||void 0===D||null===(_=D._def)||void 0===_||null===(M=_.extendedProps)||void 0===M?void 0:M.status)&&(null===(P=h()(null===e||void 0===e||null===(A=e.event)||void 0===A||null===(j=A._def)||void 0===j||null===(I=j.extendedProps)||void 0===I?void 0:I.appointmentDate))||void 0===P?void 0:P.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"Upcoming Appointment":"Missed"===(null===e||void 0===e||null===(Y=e.event)||void 0===Y||null===(N=Y._def)||void 0===N||null===(S=N.extendedProps)||void 0===S?void 0:S.status)?"Missed Appointment":"Completed Appointment"})]})})},height:"80vh",now:null,eventClick:e=>{oe(e.event),X(!0)},dayMaxEvents:1})}),(0,g.jsxs)(m.Z,{show:K,onHide:()=>{X(!1)},centered:!0,animation:!1,size:"md",className:"custom-modal",children:[(0,g.jsx)(m.Z.Header,{closeButton:!0,children:(0,g.jsx)(m.Z.Title,{className:"appointment-modal-title",children:"Booked"===(null===le||void 0===le||null===(e=le._def)||void 0===e||null===(n=e.extendedProps)||void 0===n?void 0:n.status)&&(null===(d=h()(null===le||void 0===le||null===(x=le._def)||void 0===x||null===(M=x.extendedProps)||void 0===M?void 0:M.appointmentDate))||void 0===d?void 0:d.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"Upcoming Appointment":"Missed"===(null===le||void 0===le||null===(P=le._def)||void 0===P||null===(A=P.extendedProps)||void 0===A?void 0:A.status)?"Missed Appointment":"Completed Appointment"})}),(0,g.jsxs)(m.Z.Body,{children:[(0,g.jsx)("p",{style:{color:"#1A1A1A",fontWeight:600,fontSize:"18px"},className:"mb-2",children:"Appointment"}),(0,g.jsxs)("p",{style:{color:"#1A1A1A",fontWeight:400,fontSize:"16px"},children:[ie," -"," ",null===(j=h()(null===le||void 0===le||null===(I=le._def)||void 0===I||null===(Y=I.extendedProps)||void 0===Y?void 0:Y.appointmentDate))||void 0===j?void 0:j.format("MMM-D"),". ",null===le||void 0===le||null===(N=le._def)||void 0===N||null===(S=N.extendedProps)||void 0===S?void 0:S.appointmentStartTime," -"," ",null===le||void 0===le||null===(T=le._def)||void 0===T||null===(b=T.extendedProps)||void 0===b?void 0:b.appointmentEndTime]}),(0,g.jsxs)("span",{className:"d-flex align-items-center",children:[(0,g.jsx)("img",{src:f.Z.NEW_PATIENT_GRAY,alt:"new patient icon"}),(0,g.jsx)("p",{className:"mb-0 px-2",style:{color:"#1A1A1A",fontWeight:500,fontSize:"16px"},children:null===le||void 0===le||null===(k=le._def)||void 0===k||null===(y=k.extendedProps)||void 0===y?void 0:y.doctorName})]}),(0,g.jsxs)("span",{children:[(0,g.jsx)("p",{className:"mb-0 mt-4",style:{color:"#999999",fontWeight:500,fontSize:"16px"},children:"Reason:"}),(0,g.jsx)("p",{style:{fontWeight:400,fontSize:"14px",textAlign:"justify"},children:null!==le&&void 0!==le&&null!==(w=le._def)&&void 0!==w&&null!==(Z=w.extendedProps)&&void 0!==Z&&Z.reasonForAppoinment?null===le||void 0===le||null===(C=le._def)||void 0===C||null===(E=C.extendedProps)||void 0===E?void 0:E.reasonForAppoinment:"N/A"})]}),202===(null===le||void 0===le||null===(B=le._def)||void 0===B||null===(F=B.extendedProps)||void 0===F?void 0:F.statusId)&&(0,g.jsx)(c.Z,{className:"w-100 mt-4 bg-dk-purple",onClick:()=>{var e,n;return n=null===le||void 0===le||null===(e=le._def)||void 0===e?void 0:e.extendedProps,void G(v.m.DOCTOR_DETAILS,{state:{appointmentId:null===n||void 0===n?void 0:n.appointmentId}})},children:"Reschedule Appointment"}),202===(null===le||void 0===le||null===(U=le._def)||void 0===U||null===(W=U.extendedProps)||void 0===W?void 0:W.statusId)&&(0,g.jsx)(c.Z,{className:"w-100 mt-4 bg-dk-purple",onClick:()=>{var e,n;return n=null===le||void 0===le||null===(e=le._def)||void 0===e?void 0:e.extendedProps,localStorage.setItem("slotDescription",JSON.stringify(n)),void G(v.m.PATIENT_TELE_CONSULTATION)},children:"Join Appointment"})]})]})]})})}}}]);
//# sourceMappingURL=3962.79604da8.chunk.js.map