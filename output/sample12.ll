; ModuleID = '<string>'
source_filename = "<string>"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "unknown-unknown-unknown"

; Function Attrs: norecurse nounwind readnone
define i64 @SECRET(i64 %.1) local_unnamed_addr #0 {
.3:
  %.5 = lshr i64 %.1, 24
  %0 = trunc i64 %.5 to i32
  %.7 = and i32 %0, 255
  %.11 = lshr i64 %.1, 16
  %1 = trunc i64 %.11 to i32
  %.13 = and i32 %1, 255
  %.17 = lshr i64 %.1, 8
  %2 = trunc i64 %.17 to i32
  %.19 = and i32 %2, 255
  %.23 = lshr i64 %.1, 6
  %.24 = trunc i64 %.23 to i2
  %.25 = xor i2 %.24, -1
  %.26 = zext i2 %.25 to i26
  %.29 = or i26 %.26, -33262988
  %.30 = lshr i64 %.1, 3
  %3 = trunc i64 %.30 to i29
  %.32 = and i29 %3, 7
  %.33 = zext i26 %.29 to i29
  %.34 = shl nuw i29 %.33, 3
  %.35 = or i29 %.34, %.32
  %4 = lshr i64 %.1, 2
  %5 = trunc i64 %4 to i30
  %6 = and i30 %5, 1
  %.40 = zext i29 %.35 to i30
  %7 = shl nuw i30 %.40, 1
  %.41 = or i30 %7, %6
  %.42 = xor i30 %.41, 1
  %8 = lshr i64 %.1, 1
  %9 = trunc i64 %8 to i31
  %10 = and i31 %9, 1
  %.46 = zext i30 %.42 to i31
  %.47 = shl nuw i31 %.46, 1
  %.48 = or i31 %.47, %10
  %11 = trunc i64 %.1 to i32
  %12 = and i32 %11, 1
  %.53 = zext i31 %.48 to i32
  %13 = shl nuw i32 %.53, 1
  %.54 = or i32 %13, %12
  %.55 = xor i32 %.54, 1
  %.56 = mul i32 %.55, 16777619
  %.57 = xor i32 %.56, %.19
  %.58 = mul i32 %.57, 16777619
  %.59 = xor i32 %.58, %.13
  %.60 = mul i32 %.59, 16777619
  %.61 = xor i32 %.60, %.7
  %.62 = mul i32 %.61, 16777619
  %.63 = zext i32 %.62 to i64
  ret i64 %.63
}

attributes #0 = { norecurse nounwind readnone }
