"use strict";(self.webpackChunkfamily_doc_app=self.webpackChunkfamily_doc_app||[]).push([[3962],{43962:(e,n,l)=>{l.r(n),l.d(n,{default:()=>P});var d=l(72791),o=l(90575),i=l(38217),t=l(52720),a=l(74332),s=l(57689),v=l(3810),u=l(95070),p=l(1444),r=l(36638),m=l(88135),c=l(43360),f=l(10857),x=l(72426),h=l.n(x),D=l(59434),_=l(24278),g=l(73683),M=l(80184);function P(){var e,n,l,x,P,A,j,I,S,Y,N,T,y,b,k,w,Z,C,E,B,F,O,U,W,z;const R=(0,d.useRef)(),G=(0,D.I0)(),H=JSON.parse(localStorage.getItem("family_doc_app")),L=(0,s.s0)(),[J,Q]=(0,d.useState)(),[V,q]=(0,d.useState)(null),{allAppointment:K}=(0,D.v9)((e=>e.appointment)),X=null===K||void 0===K||null===(e=K.data)||void 0===e?void 0:e.map((e=>({doctorId:null===e||void 0===e?void 0:e.doctorId,doctorName:null===e||void 0===e?void 0:e.doctorName,patientName:null===e||void 0===e?void 0:e.patientName,vonageSessionId:null===e||void 0===e?void 0:e.vonageSessionId,statusId:null===e||void 0===e?void 0:e.statusId,status:null===e||void 0===e?void 0:e.status,imageUrl:null===e||void 0===e?void 0:e.imageUrl,isDoctorMissed:null===e||void 0===e?void 0:e.isDoctorMissed,isPatientMissed:null===e||void 0===e?void 0:e.isPatientMissed,scheduleId:null===e||void 0===e?void 0:e.scheduleId,appointmentDate:null===e||void 0===e?void 0:e.appointmentDate,patientId:null===e||void 0===e?void 0:e.patientId,appointmentStartTime:null===e||void 0===e?void 0:e.appointmentStartTime,appointmentEndTime:null===e||void 0===e?void 0:e.appointmentEndTime,reasonForAppoinment:null===e||void 0===e?void 0:e.reasonForAppoinment,appointmentId:null===e||void 0===e?void 0:e.appointmentId,image:null===e||void 0===e?void 0:e.image,start:(0,g.ju)(null===e||void 0===e?void 0:e.appointmentDate,null===e||void 0===e?void 0:e.appointmentStartTime)}))),[$,ee]=(0,d.useState)(!1),[ne,le]=(0,d.useState)(!1),[de,oe]=(0,d.useState)(!1),[ie,te]=(0,d.useState)(null);(0,d.useEffect)((()=>{if(ie){var e,n,l,d;let p=h()(new Date),r=new Date("".concat(h()(null===ie||void 0===ie||null===(e=ie._def)||void 0===e||null===(n=e.extendedProps)||void 0===n?void 0:n.appointmentDate).format("YYYY-MM-DD"),"T").concat(h()(null===ie||void 0===ie||null===(l=ie._def)||void 0===l||null===(d=l.extendedProps)||void 0===d?void 0:d.appointmentStartTime,"hh:mm A").format("HH:mm:ss"))),m=h().duration(h()(r).diff(p)).asMinutes();le(m<10&&m>-15);let c=!1;var o,i,t,a,s,v,u;if(m<=60)c=!1;else(202===(null===ie||void 0===ie||null===(o=ie._def)||void 0===o?void 0:o.extendedProps.statusId)||205===(null===ie||void 0===ie||null===(i=ie._def)||void 0===i||null===(t=i.extendedProps)||void 0===t?void 0:t.statusId)&&!0===(null===ie||void 0===ie||null===(a=ie._def)||void 0===a||null===(s=a.extendedProps)||void 0===s?void 0:s.isDoctorMissed)&&!1===(null===ie||void 0===ie||null===(v=ie._def)||void 0===v||null===(u=v.extendedProps)||void 0===u?void 0:u.isPatientMissed))&&(c=!0);oe(c)}else le(!1)}),[ie]);const ae=function(){var e,n;let l=arguments.length>0&&void 0!==arguments[0]?arguments[0]:new Date(null===ie||void 0===ie||null===(e=ie._def)||void 0===e||null===(n=e.extendedProps)||void 0===n?void 0:n.appointmentDate),d=arguments.length>1&&void 0!==arguments[1]?arguments[1]:"en-US";return null===l||void 0===l?void 0:l.toLocaleDateString(d,{weekday:"long"})}();return(0,d.useEffect)((()=>{const e={patientId:null===H||void 0===H?void 0:H.userId,month:+h()(J).format("M"),statusId:"205"===V?205:"204"===V?204:"206"===V?206:"203"===V?203:"201"===V?201:null};G((0,_.Qe)(e))}),[G,J,null===H||void 0===H?void 0:H.userId,V]),(0,M.jsx)(u.Z,{className:"custom-full-calendar",children:(0,M.jsxs)(u.Z.Body,{className:"p-4",style:{borderRadius:"12px"},children:[(0,M.jsx)("span",{className:"fc-header-dropdown",children:(0,M.jsxs)(p.Z,{children:[(0,M.jsx)(p.Z.Toggle,{variant:"secondary",id:"checkbox-dropdown",children:"Appointments"}),(0,M.jsx)(p.Z.Menu,{children:(0,M.jsx)(r.Z,{children:[{label:"Missed",value:205},{label:"Upcoming",value:204},{label:"Completed",value:206},{label:"Cancelled",value:203},{label:"Pending",value:201}].map((e=>(0,M.jsx)(r.Z.Check,{type:"checkbox",label:e.label,value:e.value,checked:null!==V&&V.includes(e.value),onChange:e=>q(V===e.target.value?null:e.target.value)},e.value)))})})]})}),(0,M.jsx)("div",{className:"appointment-calender",children:(0,M.jsx)(o.Z,{plugins:[i.Z,t.Z,a.ZP],initialView:"dayGridMonth",headerToolbar:{start:"dayGridMonth,timeGridWeek,timeGridDay",center:"prev,title,next",end:""},ref:R,datesSet:()=>(e=>{var n,l,d;Q(null===e||void 0===e||null===(n=e.current)||void 0===n||null===(l=n.calendar)||void 0===l||null===(d=l.currentData)||void 0===d?void 0:d.currentDate)})(R),weekends:!0,events:X,eventContent:e=>{var n,l,d,o,i,t,a,s,v,u,p,r,m,c,f,x,D,_,g,P,A,j,I,S,Y,N;return(0,M.jsx)(M.Fragment,{children:(0,M.jsxs)("div",{className:"appointment-slot-background",style:{backgroundColor:"Booked"===(null===e||void 0===e||null===(n=e.event)||void 0===n||null===(l=n._def)||void 0===l||null===(d=l.extendedProps)||void 0===d?void 0:d.status)&&(null===(o=h()(null===e||void 0===e||null===(i=e.event)||void 0===i||null===(t=i._def)||void 0===t||null===(a=t.extendedProps)||void 0===a?void 0:a.appointmentDate))||void 0===o?void 0:o.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"#2269F2":"Missed"===(null===e||void 0===e||null===(s=e.event)||void 0===s||null===(v=s._def)||void 0===v||null===(u=v.extendedProps)||void 0===u?void 0:u.status)?"#F26522":"#44BC19"},children:[(0,M.jsx)("b",{children:"".concat(null===e||void 0===e||null===(p=e.event)||void 0===p||null===(r=p._def)||void 0===r||null===(m=r.extendedProps)||void 0===m?void 0:m.appointmentStartTime," - ").concat(null===e||void 0===e||null===(c=e.event)||void 0===c||null===(f=c._def)||void 0===f||null===(x=f.extendedProps)||void 0===x?void 0:x.appointmentEndTime)}),(0,M.jsx)("p",{className:"m-0",children:"Booked"===(null===e||void 0===e||null===(D=e.event)||void 0===D||null===(_=D._def)||void 0===_||null===(g=_.extendedProps)||void 0===g?void 0:g.status)&&(null===(P=h()(null===e||void 0===e||null===(A=e.event)||void 0===A||null===(j=A._def)||void 0===j||null===(I=j.extendedProps)||void 0===I?void 0:I.appointmentDate))||void 0===P?void 0:P.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"Upcoming Appointment":"Missed"===(null===e||void 0===e||null===(S=e.event)||void 0===S||null===(Y=S._def)||void 0===Y||null===(N=Y.extendedProps)||void 0===N?void 0:N.status)?"Missed Appointment":"Completed Appointment"})]})})},height:"80vh",now:null,allDaySlot:!1,slotEventOverlap:!0,eventClick:e=>{te(e.event),ee(!0)},dayMaxEvents:1})}),(0,M.jsxs)(m.Z,{show:$,onHide:()=>{ee(!1)},centered:!0,animation:!1,size:"md",className:"custom-modal",children:[(0,M.jsx)(m.Z.Header,{closeButton:!0,children:(0,M.jsx)(m.Z.Title,{className:"appointment-modal-title",children:"Booked"===(null===ie||void 0===ie||null===(n=ie._def)||void 0===n||null===(l=n.extendedProps)||void 0===l?void 0:l.status)&&(null===(x=h()(null===ie||void 0===ie||null===(P=ie._def)||void 0===P||null===(A=P.extendedProps)||void 0===A?void 0:A.appointmentDate))||void 0===x?void 0:x.format("YYYY-MM-DD"))>=h()(new Date).format("YYYY-MM-DD")?"Upcoming Appointment":"Missed"===(null===ie||void 0===ie||null===(j=ie._def)||void 0===j||null===(I=j.extendedProps)||void 0===I?void 0:I.status)?"Missed Appointment":"Completed Appointment"})}),(0,M.jsxs)(m.Z.Body,{children:[(0,M.jsx)("p",{style:{color:"#1A1A1A",fontWeight:600,fontSize:"18px"},className:"mb-2",children:"Appointment"}),(0,M.jsxs)("p",{style:{color:"#1A1A1A",fontWeight:400,fontSize:"16px"},children:[ae," -"," ",null===(S=h()(null===ie||void 0===ie||null===(Y=ie._def)||void 0===Y||null===(N=Y.extendedProps)||void 0===N?void 0:N.appointmentDate))||void 0===S?void 0:S.format("MMM-D"),". ",null===ie||void 0===ie||null===(T=ie._def)||void 0===T||null===(y=T.extendedProps)||void 0===y?void 0:y.appointmentStartTime," -"," ",null===ie||void 0===ie||null===(b=ie._def)||void 0===b||null===(k=b.extendedProps)||void 0===k?void 0:k.appointmentEndTime]}),(0,M.jsxs)("span",{className:"d-flex align-items-center",children:[(0,M.jsx)("img",{src:f.Z.NEW_PATIENT_GRAY,alt:"new patient icon"}),(0,M.jsx)("p",{className:"mb-0 px-2",style:{color:"#1A1A1A",fontWeight:500,fontSize:"16px"},children:null===ie||void 0===ie||null===(w=ie._def)||void 0===w||null===(Z=w.extendedProps)||void 0===Z?void 0:Z.doctorName})]}),(0,M.jsxs)("span",{children:[(0,M.jsx)("p",{className:"mb-0 mt-4",style:{color:"#999999",fontWeight:500,fontSize:"16px"},children:"Reason:"}),(0,M.jsx)("p",{style:{fontWeight:400,fontSize:"14px",textAlign:"justify"},children:null!==ie&&void 0!==ie&&null!==(C=ie._def)&&void 0!==C&&null!==(E=C.extendedProps)&&void 0!==E&&E.reasonForAppoinment?null===ie||void 0===ie||null===(B=ie._def)||void 0===B||null===(F=B.extendedProps)||void 0===F?void 0:F.reasonForAppoinment:"N/A"})]}),202===(null===ie||void 0===ie||null===(O=ie._def)||void 0===O||null===(U=O.extendedProps)||void 0===U?void 0:U.statusId)&&(0,M.jsx)(c.Z,{className:"w-100 mt-4 bg-dk-purple",onClick:()=>{var e,n;return n=null===ie||void 0===ie||null===(e=ie._def)||void 0===e?void 0:e.extendedProps,void L(v.m.DOCTOR_DETAILS,{state:{appointmentId:null===n||void 0===n?void 0:n.appointmentId}})},children:"Reschedule Appointment"}),202===(null===ie||void 0===ie||null===(W=ie._def)||void 0===W||null===(z=W.extendedProps)||void 0===z?void 0:z.statusId)&&(0,M.jsx)(c.Z,{className:"w-100 mt-4 bg-dk-purple",onClick:()=>{var e,n;return n=null===ie||void 0===ie||null===(e=ie._def)||void 0===e?void 0:e.extendedProps,localStorage.setItem("slotDescription",JSON.stringify(n)),void L(v.m.PATIENT_TELE_CONSULTATION)},children:"Join Appointment"})]})]})]})})}}}]);
//# sourceMappingURL=3962.9b40c050.chunk.js.map