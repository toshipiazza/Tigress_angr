; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "unknown-unknown-unknown"

; Function Attrs: norecurse nounwind readnone
define i64 @SECRET(i64 %.1) local_unnamed_addr #0 {
.3:
  %0 = trunc i64 %.1 to i32
  %.7 = and i32 %0, 255
  %.11 = add nuw nsw i32 %.7, 1
  %1 = urem i32 %.11, 65521
  %.19 = lshr i64 %.1, 8
  %2 = trunc i64 %.19 to i32
  %.21 = and i32 %2, 255
  %.25 = add nuw nsw i32 %1, %.21
  %3 = urem i32 %.25, 65521
  %.33 = lshr i64 %.1, 16
  %4 = trunc i64 %.33 to i32
  %.35 = and i32 %4, 255
  %.39 = add nuw nsw i32 %3, %.35
  %5 = urem i32 %.39, 65521
  %.47 = lshr i64 %.1, 24
  %6 = trunc i64 %.47 to i32
  %.49 = and i32 %6, 255
  %.53 = add nuw nsw i32 %5, %.49
  %7 = urem i32 %.53, 65521
  %.61 = lshr i64 %.1, 32
  %8 = trunc i64 %.61 to i32
  %.63 = and i32 %8, 255
  %.67 = add nuw nsw i32 %7, %.63
  %9 = urem i32 %.67, 65521
  %.75 = lshr i64 %.1, 40
  %10 = trunc i64 %.75 to i32
  %.77 = and i32 %10, 255
  %.81 = add nuw nsw i32 %9, %.77
  %11 = urem i32 %.81, 65521
  %.89 = lshr i64 %.1, 48
  %12 = trunc i64 %.89 to i32
  %.91 = and i32 %12, 255
  %.95 = add nuw nsw i32 %11, %.91
  %13 = urem i32 %.95, 65521
  %.103 = lshr i64 %.1, 56
  %14 = trunc i64 %.103 to i32
  %.105 = and i32 %14, 255
  %.109 = add nuw nsw i32 %13, %.105
  %15 = urem i32 %.109, 65521
  %.516 = add nuw nsw i32 %3, %1
  %16 = urem i32 %.516, 65521
  %.524 = add nuw nsw i32 %5, %16
  %17 = urem i32 %.524, 65521
  %.532 = add nuw nsw i32 %7, %17
  %18 = urem i32 %.532, 65521
  %.540 = add nuw nsw i32 %9, %18
  %19 = urem i32 %.540, 65521
  %.548 = add nuw nsw i32 %11, %19
  %20 = urem i32 %.548, 65521
  %.556 = add nuw nsw i32 %13, %20
  %21 = urem i32 %.556, 65521
  %.564 = add nuw nsw i32 %15, %21
  %22 = urem i32 %.564, 65521
  %.574 = shl nuw i32 %22, 16
  %.688 = or i32 %.574, %15
  %.689 = zext i32 %.688 to i64
  ret i64 %.689
}

attributes #0 = { norecurse nounwind readnone }
