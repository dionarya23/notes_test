import { z } from "zod";

export const CreateNoteScheme = z.object({
  title: z.string().min(1, "Title required"),
  body: z.string(),
});
