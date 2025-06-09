import { Webhook } from "svix";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma"; // ✅ Use wrapper

export async function POST(req: Request) {
  const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET || "";

  const payload = await req.text();
  const headerPayload = headers(); 
  const svix_id = (await headerPayload).get("svix-id")!;
  const svix_timestamp = (await headerPayload).get("svix-timestamp")!;
  const svix_signature = (await headerPayload).get("svix-signature")!;

  const wh = new Webhook(WEBHOOK_SECRET);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let evt: any;

  try {
    evt = wh.verify(payload, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    });
  } catch (err) {
    console.error("Webhook verification failed:", err);
    return NextResponse.json({ error: "Invalid webhook" }, { status: 400 });
  }

  const { id, email_addresses, first_name, last_name } = evt.data;

  if (evt.type === "user.created") {
    await prisma.user.create({
      data: {
        clerkId: id,
        email: email_addresses[0].email_address,
        firstName: first_name,
        lastName: last_name,
      },
    });
  }

  return NextResponse.json({ success: true }, { status: 200 });
}
