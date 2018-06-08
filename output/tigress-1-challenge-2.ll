; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "unknown-unknown-unknown"

; Function Attrs: norecurse nounwind readnone
define i64 @SECRET(i64 %.1) local_unnamed_addr #0 {
.3:
  %.197 = add i64 %.1, -902749805
  %0 = udiv i64 %.1, 7
  %1 = trunc i64 %0 to i3
  %.207 = shl i3 %1, 1
  %2 = lshr i64 %0, 1
  %.215 = trunc i64 %2 to i3
  %.216 = or i3 %.207, %.215
  %.222 = zext i3 %.216 to i6
  %.223 = shl nuw nsw i6 %.222, 1
  %.224 = or i6 %.223, 1
  %.225 = sub nsw i6 0, %.224
  %.226 = zext i6 %.225 to i64
  %.230 = lshr i64 %.197, %.226
  %.256 = zext i3 %.216 to i64
  %.257 = shl nuw nsw i64 %.256, 1
  %.258 = or i64 %.257, 1
  %.259 = shl i64 %.197, %.258
  %.260 = or i64 %.230, %.259
  %3 = lshr i64 %0, 3
  %.297 = and i64 %3, 14
  %.298 = or i64 %.297, 1
  %.299 = shl i64 127996265, %.298
  %4 = lshr i64 %.299, 4
  %.309 = and i64 %4, 14
  %.310 = or i64 %.309, 1
  %.311 = shl i64 %.1, %.310
  %5 = trunc i64 %4 to i5
  %6 = and i5 %5, 14
  %7 = or i5 %6, 1
  %.361 = zext i5 %7 to i6
  %.362 = sub nsw i6 0, %.361
  %.363 = zext i6 %.362 to i64
  %.367 = lshr i64 %.1, %.363
  %.368 = or i64 %.367, %.311
  %.369 = mul i64 %.1, 343000538
  %.370 = add i64 %.369, 1638886
  %8 = lshr i64 %.370, 18
  %.379 = and i64 %8, 14
  %.380 = or i64 %.379, 1
  %.381 = shl i64 %.368, %.380
  %9 = trunc i64 %8 to i5
  %10 = and i5 %9, 14
  %11 = or i5 %10, 1
  %.503 = zext i5 %11 to i6
  %.504 = sub nsw i6 0, %.503
  %.505 = zext i6 %.504 to i64
  %.509 = lshr i64 %.368, %.505
  %.38228 = or i64 %.381, %.509
  %12 = lshr i64 %.38228, 4
  %.519 = and i64 %12, 14
  %.520 = or i64 %.519, 1
  %.521 = lshr i64 %.260, %.520
  %13 = trunc i64 %12 to i5
  %14 = and i5 %13, 14
  %15 = or i5 %14, 1
  %.845 = zext i5 %15 to i6
  %.846 = sub nsw i6 0, %.845
  %.847 = zext i6 %.846 to i64
  %.851 = shl i64 %.260, %.847
  %.852 = or i64 %.851, %.521
  ret i64 %.852
}

attributes #0 = { norecurse nounwind readnone }
