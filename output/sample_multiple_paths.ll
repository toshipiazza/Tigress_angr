; ModuleID = '<string>'
source_filename = "<string>"
target triple = "unknown-unknown-unknown"

; Function Attrs: norecurse nounwind readnone
define i64 @SECRET(i64 %.1) local_unnamed_addr #0 {
.3:
  %.5 = icmp ult i64 %.1, 2048
  br i1 %.5, label %.3.if, label %.3.endif

.3.if:                                            ; preds = %.3.endif.endif.endif, %.3.endif.endif, %.3.endif, %.3
  %merge = phi i64 [ 0, %.3 ], [ 1, %.3.endif ], [ 2, %.3.endif.endif ], [ 3, %.3.endif.endif.endif ]
  ret i64 %merge

.3.endif:                                         ; preds = %.3
  %.17 = icmp ult i64 %.1, 4194304
  br i1 %.17, label %.3.if, label %.3.endif.endif

.3.endif.endif:                                   ; preds = %.3.endif
  %.38 = icmp ult i64 %.1, 8589934592
  br i1 %.38, label %.3.if, label %.3.endif.endif.endif

.3.endif.endif.endif:                             ; preds = %.3.endif.endif
  %.68 = icmp ult i64 %.1, 17592186044416
  br i1 %.68, label %.3.if, label %.3.endif.endif.endif.endif

.3.endif.endif.endif.endif:                       ; preds = %.3.endif.endif.endif
  %.107 = icmp ult i64 %.1, 36028797018963968
  %spec.select = select i1 %.107, i64 4, i64 5
  ret i64 %spec.select
}

attributes #0 = { norecurse nounwind readnone }
