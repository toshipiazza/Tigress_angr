; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "unknown-unknown-unknown"

; Function Attrs: norecurse nounwind readnone
define i64 @SECRET(i64 %.1) local_unnamed_addr #0 {
.3:
  %const = bitcast i64 -7070675565921424023 to i64
  %.5 = lshr i64 %.1, 32
  %.24 = shl i64 %.1, 3
  %.25 = and i64 %.24, 34359738360
  %.27 = add nuw nsw i64 %.25, 8
  %.28 = xor i64 %.27, %.5
  %.29 = mul i64 %.28, %const
  %.30 = xor i64 %.29, %.5
  %.50 = lshr i64 %.29, 47
  %.56 = xor i64 %.30, %.50
  %.57 = mul i64 %.56, %const
  %.111 = lshr i64 %.57, 47
  %.117 = xor i64 %.111, %.57
  %.118 = mul i64 %.117, %const
  ret i64 %.118
}

attributes #0 = { norecurse nounwind readnone }
